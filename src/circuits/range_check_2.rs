use std::marker::PhantomData;

use eth_types::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Assigned, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
    poly::Rotation,
};

#[derive(Debug, Clone)]
/// A range-constrained value in the circuit produced by the RangeCheckConfig.
struct RangeConstrained<F: Field, const RANGE: usize>(AssignedCell<Assigned<F>, F>);

#[derive(Debug, Clone)]
struct RangeCheckConfig<F: Field, const RANGE: usize> {
    value: Column<Advice>,
    q_range_check: Selector,
    _marker: PhantomData<F>,
}

impl<F: Field, const RANGE: usize> RangeCheckConfig<F, RANGE> {
    pub fn configure(meta: &mut ConstraintSystem<F>, value: Column<Advice>) -> Self {
        let q_range_check = meta.selector();

        meta.create_gate("range check", |meta| {
            //        value     |    q_range_check
            //       ------------------------------
            //          v       |         1

            let q = meta.query_selector(q_range_check);
            let value = meta.query_advice(value, Rotation::cur());

            vec![q * value] 
        });

        Self {
            q_range_check,
            value,
            _marker: PhantomData,
        }
    }

    pub fn assign(
        &self,
        mut layouter: impl Layouter<F>,
        value: Value<Assigned<F>>,
    ) -> Result<RangeConstrained<F, RANGE>, Error> {
        layouter.assign_region(
            || "Assign value",
            |mut region| {
                let offset = 0;

                // Enable q_range_check
                self.q_range_check.enable(&mut region, offset)?;

                let range_check = |range: usize, value: Value<Assigned<F>>| {
                    assert!(range > 0);
                    (1..range).fold(value.clone(), |expr, i| {
                        expr * (Value::<Assigned<F>>::known(F::from(i as u64).into()) - value.clone())
                    })
                };

                // Assign value
                region
                    .assign_advice(|| "value", self.value, offset, || range_check(RANGE, value))
                    .map(RangeConstrained)
            },
        )
    }
}


#[cfg(test)]
mod tests {
    use halo2_proofs::{
        circuit::floor_planner::V1,
        dev::{MockProver},
        halo2curves::bn256::Fr as Fp,
        plonk::{Circuit},
    };

    use super::*;

    #[derive(Default)]
    struct MyCircuit<F: Field, const RANGE: usize> {
        value: Value<Assigned<F>>,
    }

    impl<F: Field, const RANGE: usize> Circuit<F> for MyCircuit<F, RANGE> {
        type Config = RangeCheckConfig<F, RANGE>;
        // or SimpleFloorPlanner
        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let value = meta.advice_column();
            RangeCheckConfig::configure(meta, value)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            config.assign(layouter.namespace(|| "Assign value"), self.value)?;

            Ok(())
        }
    }

    #[test]
    fn test_range_check_1() {
        let k = 4;
        const RANGE: usize = 8; // 3-bit value

        // Successful cases
        for i in 0..RANGE {
            let circuit = MyCircuit::<Fp, RANGE> {
                value: Value::known(Fp::from(i as u64).into()),
            };

            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            prover.assert_satisfied();
        }

        // fail case
        // let circuit = MyCircuit::<Fp, RANGE> {
        //     value: Value::known(Fp::from(9 as u64).into()),
        // };

        // let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        // prover.assert_satisfied();
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn print_range_check_1() {
        use plotters::prelude::*;

        let root = BitMapBackend::new("range-check-1-layout.png", (1024, 3096)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Range Check 1 Layout", ("sans-serif", 60))
            .unwrap();

        let circuit = MyCircuit::<Fp, 8> {
            value: Value::unknown(),
        };
        halo2_proofs::dev::CircuitLayout::default()
            .render(3, &circuit, &root)
            .unwrap();
    }
}