use bptree::BPTreeSet;
use criterion::{Criterion, criterion_group, criterion_main};
use rand::seq::SliceRandom;
use rand::{Rng, rng};
use std::fs;
use std::hint::black_box;

fn setup_bptree(num_elements: u32) -> BPTreeSet {
    let _ = fs::remove_file("./bptree");
    let mut btree = BPTreeSet::new().unwrap();
    for i in 0..num_elements {
        btree.add(i as u128).unwrap();
    }
    btree
}

fn bench_random_add(c: &mut Criterion) {
    let mut group = c.benchmark_group("BTreeSet Add");

    // 100개, 1000개, 10000개, 100,000개 삽입 성능 측정
    for &size in [100, 1_000, 10_000, 100_000].iter() {
        group.bench_function(format!("Insert {} elements", size), |b| {
            let mut rng = rng();
            let mut values: Vec<u128> = (0..size).map(|i| i as u128).collect();
            values.shuffle(&mut rng);

            b.iter_with_setup(
                || {
                    // 각 반복마다 새로운 빈 B-Tree를 생성
                    let _ = fs::remove_file("./bptree");
                    BPTreeSet::new().unwrap()
                },
                |mut btree| {
                    // 지정된 개수만큼 삽입
                    for &value in &values {
                        btree.add(black_box(value)).unwrap();
                    }
                },
            );
        });
    }
    group.finish();
}

fn bench_random_has(c: &mut Criterion) {
    let mut group = c.benchmark_group("BTreeSet Has");

    for size in [1_000, 10_000, 100_000].iter() {
        let btree = setup_bptree(*size as u32);
        let mut rng = rng();
        let mut values_to_find: Vec<u128> = (0..*size).map(|i| i as u128).collect();
        values_to_find.shuffle(&mut rng);

        group.bench_function(format!("Random Has from {}", size), |b| {
            b.iter(|| {
                // 찾을 값 100개를 무작위로 선택
                for _ in 0..100 {
                    let index = rng.random_range(0..values_to_find.len());
                    btree.has(black_box(values_to_find[index])).unwrap();
                }
            })
        });
    }
    group.finish();
}

criterion_group!(benches, bench_random_add, bench_random_has);
criterion_main!(benches);
