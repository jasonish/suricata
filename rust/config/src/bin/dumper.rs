use suricata_config::{dump_node, load_from_file};

fn main() {
    let filename = std::env::args().nth(1).unwrap();
    let root = load_from_file(filename).unwrap();
    dump_node(&root, vec![]);
}
