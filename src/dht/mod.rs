#![expect(dead_code)]
mod actor;
mod table;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct NodeId([u8; 20]);

impl NodeId {
    fn get_bit(&self, i: usize) -> bool {
        assert!(
            i < 160,
            "NodeId::get_bit() called with out-of-range value {i}"
        );
        let byteno = i / 8;
        let bitno = 7 - (i % 8);
        self.0[byteno] & (1 << bitno) != 0
    }
}
