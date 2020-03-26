#![no_std]
#![feature(proc_macro_hygiene)]
extern crate ontio_std as ostd;
use ostd::abi::{Encoder,EventBuilder, Sink, Source};
use ostd::{database, runtime};
use ostd::prelude::*;
use ostd::macros::base58;

struct CompactMerkleTree {
    tree_size: u32,
    hashes: Vec<H256>,
}

fn load_merkletree() -> Option<CompactMerkleTree> {
    let value = runtime::storage_read(merkletree_key)?;
    let mut source = Source::new(&value);
    let tree_size = source.read_u32().ok()?;
    let len = source.read_u32().ok()?;
    let mut hashes:Vec<H256> = Vec::with_capacity(len as usize);
    for _i in 0..len {
        let hash = source.read_h256().ok()?;
        hashes.push(hash.clone());
    }

    return Some(CompactMerkleTree{ tree_size, hashes})
}

fn store_merkletree(tree: &CompactMerkleTree) {
    let mut sink = Sink::new(4 + 4 + tree.hashes.len()*32);
    sink.write(tree.tree_size);
    sink.write(tree.hashes.len() as u32);
    for hash in tree.hashes.iter() {
        sink.write(hash);
    }

    runtime::storage_write(merkletree_key, sink.bytes());
}

impl CompactMerkleTree {
    fn append_hash(&mut self, mut leaf:H256) {
        let mut size = self.hashes.len();
        assert_ne!(self.tree_size, u32::max_value());
        let mut s = self.tree_size;
        loop {
            if s%2==1 {
                break;
            }
            s = s/2;
            leaf = self.hash_children(&self.hashes[size-1], &leaf);
            size -= 1;
        }
        self.tree_size += 1;
        self.hashes.resize_with(size +1, ||H256([0;32]));
        self.hashes[size] = leaf;
    }

    fn hash_children(&self, left: &H256, right: &H256) -> H256 {
        let mut data = vec![1u8];
        let mut data = [1;65];
        data[1..33].clone_from_slice(left.as_ref());
        data[33..65].clone_from_slice(right.as_ref());
        return runtime::sha256(&data[..]);
    }
}

#[derive(Encoder)]
struct RootSize {
    root:H256,
    tree_size:u32,
}

const owner_key:&[u8] = b"owner_key";
const merkletree_key:&[u8] = b"mt";
const ADMIN: Address = base58!("ASWTacJZSwozPfjQAe4Bq2saMEZ3aEQK8j");

fn get_root_inner(ogq_tree: &mut CompactMerkleTree) -> H256 {
    if ogq_tree.hashes.len() != 0 {
        let mut l = ogq_tree.hashes.len();
        let mut accum: H256 = ogq_tree.hashes[l - 1].clone();
        let mut i = l-2;
        loop {
            if i < 0 {
                break;
            }
            i -= 1;
            accum = ogq_tree.hash_children(&ogq_tree.hashes[i], &accum);
        }
        return accum;
    } else {
        return runtime::sha256(b"");
    }
}

fn set_owner(addr: &Address) -> bool {
    assert!(runtime::check_witness(&ADMIN));
    database::put(owner_key, addr);
    EventBuilder::new().address(addr).notify();
    true
}

fn batch_add2(hash_list: Vec<Vec<u8>>) -> bool {
    let owner:Address = database::get(owner_key).unwrap();
    assert!(runtime::check_witness(&owner));
    if hash_list.len() == 0 {
        return false;
    }
    let mut ogq_tree:CompactMerkleTree = load_merkletree().expect("load merkletree error");
    for h in hash_list.iter() {
        let t = H256::from_slice(h);
        ogq_tree.append_hash(t);
    }
    store_merkletree(&ogq_tree);
    let root = get_root_inner(&mut ogq_tree);
    EventBuilder::new().h256(root).number(ogq_tree.tree_size as u128);
    true
}

fn batch_add(hash_list: &[&H256]) -> bool {
    let owner:Address = database::get(owner_key).expect("get owner address error");
    assert!(runtime::check_witness(&owner));
    if hash_list.len() == 0 {
        return false;
    }
    let mut ogq_tree:CompactMerkleTree = load_merkletree().expect("load merkletree error");
    for &h in hash_list.iter() {
        ogq_tree.append_hash(h.clone());
    }
    store_merkletree(&ogq_tree);
    let root = get_root_inner(&mut ogq_tree);
    EventBuilder::new().h256(root).number(ogq_tree.tree_size as u128);
    return true
}

fn get_root() -> RootSize {
    let mut ogq_tree:CompactMerkleTree = load_merkletree().expect("load merkletree error");
    let root = get_root_inner(&mut ogq_tree);
    let root_size = RootSize{
        root,
        tree_size:ogq_tree.tree_size,
    };
    EventBuilder::new().h256(root).number(ogq_tree.tree_size as u128).notify();
    return root_size;
}

fn contract_migrate(code:&[u8]) -> bool {
    assert!(runtime::check_witness(&ADMIN));
    let addr:Address = runtime::contract_migrate(code, 3, "name", "version", "author", "email", "desc");
    EventBuilder::new().address(&addr).notify();
    true
}

fn contract_destroy() -> bool {
    assert!(runtime::check_witness(&ADMIN));
    runtime::contract_delete();
}

#[no_mangle]
pub fn invoke() {
    let input = runtime::input();
    let mut source = Source::new(&input);
    let action = source.read().unwrap();
    let mut sink = Sink::new(12);
    match action {
        "set_owner" => {
            let owner:Address = source.read().unwrap();
            sink.write(set_owner(&owner));
        },
        "batch_add" => {
            let hash_list:Vec<&H256> = source.read().unwrap();
            sink.write(batch_add(hash_list.as_slice()));
        },
        "batch_add2" => {
            let hash_list:Vec<Vec<u8>> = source.read().unwrap();
            sink.write(batch_add2(hash_list));
        },
        "get_root" => {
            sink.write(get_root());
        },
        "contract_migrate" => {
            let code = source.read().unwrap();
            sink.write(contract_migrate(code));
        },
        "contract_destroy" => sink.write(contract_destroy()),
        _ => panic!("unsupported action!"),
    }
    runtime::ret(sink.bytes())
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
