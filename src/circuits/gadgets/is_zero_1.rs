//! IsZero gadget works as follows:
//!
//! Given a `value` to be checked if it is zero:
//!  - witnesses `inv0(value)`, where `inv0(x)` is 0 when `x` = 0, and
//!  `1/x` otherwise

use eth_types::Field;
use halo2_proofs::{
    circuit::{Chip, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, VirtualCells},
    poly::Rotation,
};

/// Trait that needs to be implemented for any gadget or circuit that wants to
/// implement `IsZero`.
pub trait IsZeroInstruction<F: Field> {
    /// Given a `value` to be checked if it is zero:
    ///   - witnesses `inv0(value)`, where `inv0(x)` is 0 when `x` = 0, and `1/x` otherwise
    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: Value<F>,
    ) -> Result<(), Error>;
}

/// Config struct representing the required fields for an `IsZero` config to
/// exist.
#[derive(Clone, Debug)]
pub struct IsZeroConfig<F> {
    /// Modular inverse of the value.
    pub value_inv: Column<Advice>,
    /// This can be used directly for custom gate at the offset if `is_zero` is
    /// called, it will be 1 if `value` is zero, and 0 otherwise.
    pub is_zero_expression: Expression<F>,
}

/// Wrapper arround [`IsZeroConfig`] for which [`Chip`] is implemented.
#[derive(Clone, Debug)]
pub struct IsZeroChip<F> {
    config: IsZeroConfig<F>,
}

#[rustfmt::skip]
impl<F: Field> IsZeroChip<F> {
    /// Sets up the configuration of the chip by creating the required columns
    /// and defining the constraints that take part when using `is_zero` gate.
    ///
    /// Truth table of iz_zero gate:
    /// +----+-------+-----------+-----------------------+---------------------------------+-------------------------------------+
    /// | ok | value | value_inv | 1 - value ⋅ value_inv | value ⋅ (1 - value ⋅ value_inv) | value_inv ⋅ (1 - value ⋅ value_inv) |
    /// +----+-------+-----------+-----------------------+---------------------------------+-------------------------------------+
    /// | V  | 0     | 0         | 1                     | 0                               | 0                                   |
    /// |    | 0     | x         | 1                     | 0                               | x                                   |
    /// |    | x     | 0         | 1                     | x                               | 0                                   |
    /// | V  | x     | 1/x       | 0                     | 0                               | 0                                   |
    /// |    | x     | y         | 1 - xy                | x(1 - xy)                       | y(1 - xy)                           |
    /// +----+-------+-----------+-----------------------+---------------------------------+-------------------------------------+
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        q_enable: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
        value: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
        value_inv: Column<Advice>,
    ) -> IsZeroConfig<F> {
        // dummy initialization
        let mut is_zero_expression = Expression::Constant(F::ZERO);

        meta.create_gate("is_zero gate", |meta| {
            let q_enable = q_enable(meta);

            let value_inv = meta.query_advice(value_inv, Rotation::cur());
            let value = value(meta);

            is_zero_expression = Expression::Constant(F::ONE) - value.clone() * value_inv;

            // We wish to satisfy the below constrain for the following cases:
            //
            // 1. value == 0
            // 2. if value != 0, require is_zero_expression == 0 => value_inv == value.invert()
            [q_enable * value * is_zero_expression.clone()]
        });

        IsZeroConfig::<F> {
            value_inv,
            is_zero_expression,
        }
    }

    /// Given an `IsZeroConfig`, construct the chip.
    pub fn construct(config: IsZeroConfig<F>) -> Self {
        IsZeroChip { config }
    }
}

impl<F: Field> IsZeroInstruction<F> for IsZeroChip<F> {
    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: Value<F>,
    ) -> Result<(), Error> {
        let config = self.config();
        // postpone the invert to prover which has batch_invert function to
        // amortize among all is_zero_chip assignments.
        let value_invert = value.into_field().invert();
        region.assign_advice(
            || "witness inverse of value",
            config.value_inv,
            offset,
            || value_invert,
        )?;

        Ok(())
    }
}

impl<F: Field> Chip<F> for IsZeroChip<F> {
    type Config = IsZeroConfig<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

mod test {
    use super::{IsZeroChip, IsZeroConfig, IsZeroInstruction};

    use eth_types::Field;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        halo2curves::bn256::Fr as Fp,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector, Instance},
        poly::Rotation,
    };
    use std::marker::PhantomData;

    use halo2_proofs::dev::CircuitLayout;
    use plotters::prelude::*;

    macro_rules! try_test_circuit {
        ($value:expr) => {{
            let circuit = TestCircuit::<Fp> {
                value: $value,
                _marker: PhantomData,
            };
            let prover = MockProver::<Fp>::run(4, &circuit, vec![vec![Fp::from(1)]]).unwrap();
            prover.assert_satisfied()
        }};
    }

    #[test]
    fn row_diff_is_zero() {
        #[derive(Clone, Debug)]
        struct TestCircuitConfig<F> {
            q_enable: Selector,
            value: Column<Advice>,
            instance: Column<Instance>,
            is_zero: IsZeroConfig<F>,
        }

        #[derive(Default)]
        struct TestCircuit<F: Field> {
            value: u64,
            _marker: PhantomData<F>,
        }

        impl<F: Field> Circuit<F> for TestCircuit<F> {
            type Config = TestCircuitConfig<F>;
            type FloorPlanner = SimpleFloorPlanner;
            #[cfg(feature = "circuit-params")]
            type Params = ();

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                let q_enable = meta.complex_selector();
                let value = meta.advice_column();
                let value_inv = meta.advice_column();
                let instance = meta.instance_column();

                meta.enable_equality(instance);
                meta.enable_equality(value);

                let is_zero = IsZeroChip::configure(
                    meta,
                    |meta| meta.query_selector(q_enable),
                    |meta| {
                        meta.query_advice(value, Rotation::cur())
                    },
                    value_inv,
                );

                let config = Self::Config {
                    q_enable,
                    value,
                    instance,
                    is_zero,
                };

                config
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<F>,
            ) -> Result<(), Error> {
                let chip = IsZeroChip::construct(config.is_zero.clone());

                let v = Value::known(F::from(self.value));
                let out = layouter.assign_region(
                    || "witness",
                    |mut region| {
                        config.q_enable.enable(&mut region, 0)?;

                        region.assign_advice(
                            || "value",
                            config.value,
                            0,
                            || v.clone(),
                        )?;

                        chip.assign(&mut region, 0, v.clone())?;

                        // let value_invert = if self.value != 0 {
                        //     (1.0 / self.value as f64) as u64
                        // } else {
                        //     0 as u64
                        // };

                        let is_zero = if self.value != 0 {
                            0 as u64
                        } else {
                            1 as u64
                        };
                        region.assign_advice(
                            || "instance",
                            config.value,
                            1,
                            || Value::known(F::from(is_zero)),
                        )
                    },
                )?;

                // Ok(())
                layouter
                    .namespace(|| "out")
                    .constrain_instance(out.cell(), config.instance, 0)
            }
        }

        // ok
        try_test_circuit!(0 as u64);
    }
}
