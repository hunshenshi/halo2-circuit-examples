use std::marker::PhantomData;

use eth_types::Field;
use halo2_proofs::{
    circuit::{Chip, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, VirtualCells, Fixed, Instance, Selector},
    poly::Rotation,
};

/// Config for the IsEqual chip.
#[derive(Clone, Debug)]
pub struct IsEqualConfig {
    a: Column<Advice>,
    b: Column<Advice>,  
    zero: Column<Fixed>,
    q_enable: Selector, 
}

/// Chip that compares equality between two expressions.
#[derive(Clone, Debug)]
pub struct IsEqualChip<F: Field> {
    /// Config for the IsEqual chip.
    pub(crate) config: IsEqualConfig,
    _marker: PhantomData<F>,
}

impl<F: Field> IsEqualChip<F> {
    /// Configure the IsEqual chip.
    pub fn configure(meta: &mut ConstraintSystem<F>) -> IsEqualConfig {
        let selector = meta.selector();

        let a = meta.advice_column();
        let b = meta.advice_column();
        let zero = meta.fixed_column();

        meta.enable_equality(a);
        meta.enable_equality(b);
        meta.enable_constant(zero);

        meta.create_gate("is_equal gate", |meta| {
            let selector = meta.query_selector(selector);
            // let selector = q_enable(meta);

            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            let zero = meta.query_fixed(zero, Rotation::cur());

            [selector * (a - b - zero)]
        });

        IsEqualConfig {
            a,
            b,
            zero,
            q_enable: selector,
        }
    }

    /// Construct an IsEqual chip given a config.
    pub fn construct(config: IsEqualConfig) -> Self {
        Self { 
            config,
            _marker: PhantomData,
        }
    }
}

impl<F: Field> Chip<F> for IsEqualChip<F> {
    type Config = IsEqualConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use eth_types::Field;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        halo2curves::bn256::Fr as Fp,
        plonk::{Circuit, ConstraintSystem, Error, Selector},
    };
    
    use super::{IsEqualChip, IsEqualConfig};

    #[derive(Clone, Debug)]
    struct TestCircuitConfig {
        // q_enable: Selector,         // selector error
        is_equal: IsEqualConfig,
    }

    #[derive(Default)]
    struct TestCircuit<F: Field> {
        pub a: Value<F>,
        pub b: Value<F>,
        // pub zero: Value<F>,
    }

    impl<F: Field> Circuit<F> for TestCircuit<F> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let q_enable = meta.selector();
            let config = IsEqualChip::configure(meta);

            Self::Config {
                // q_enable,
                is_equal: config,
            }
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
            let chip = IsEqualChip::<F>::construct(config.is_equal.clone());

            layouter.assign_region(
                || "witness",
                |mut region| {
                    // let _ = config.q_enable.enable(&mut region, 0);
                    let _ = chip.config.q_enable.enable(&mut region, 0);

                    region.assign_advice(|| "a", chip.config.a, 0, || self.a)?;
                    region.assign_advice(|| "b", chip.config.b, 0, || self.b)?;
                    region.assign_fixed(|| "zero", chip.config.zero, 0, || Value::<F>::known(F::ZERO))?;

                    Ok(())
                },
            )

        }
    }

    macro_rules! try_test {
        ($a:expr, $b:expr, $is_ok_or_err:ident) => {
            // let k = usize::BITS - $values.len().leading_zeros() + 2;
            let circuit = TestCircuit::<Fp> {
                a: $a,
                b: $b,
                // zero: $c,
            };
            let prover = MockProver::<Fp>::run(4, &circuit, vec![]).unwrap();
            assert!(prover.verify().$is_ok_or_err());
        };
    }

    #[test]
    fn is_equal_gadget() {
        try_test!(
            Value::known(Fp::from(2)),
            Value::known(Fp::from(2)),
            // Value::known(Fp::from(0)),
            is_ok
        );
        try_test!(
            Value::known(Fp::from(13)),
            Value::known(Fp::from(13)),
            // Value::known(Fp::from(0)),
            is_ok
        );
        try_test!(
            Value::known(Fp::from(2)),
            Value::known(Fp::from(3)),
            // Value::known(Fp::from(0)),
            is_err
        );
    }
}