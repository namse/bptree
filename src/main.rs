use std::os::fd::AsRawFd;

struct BPTreeSet {
    file: std::fs::File,
}

impl BPTreeSet {
    fn new() -> std::io::Result<Self> {
        Ok(BPTreeSet {
            file: std::fs::OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .open("./bptree")?,
        })
    }
    fn add(&mut self, value: u128) -> std::io::Result<()> {
        let root_node_offset = self.root_node_offset()?;

        let AddAndSplitResult::Splited {
            right_node_offset,
            key,
        } = self.add_and_split_if_full(root_node_offset, value)?
        else {
            return Ok(());
        };

        let new_root_offset = self.allocate_node_offset()?;
        let new_root_node = InternalNode::new(root_node_offset, new_root_offset, key);
        self.update_file_block(new_root_offset, new_root_node.bytes())?;
        self.update_root_node_offset(new_root_offset)?;
        Ok(())
    }
    fn add_and_split_if_full(
        &mut self,
        node_offset: u64,
        value: u128,
    ) -> std::io::Result<AddAndSplitResult> {
        let node = self.node_from_offset(node_offset)?;
        match node {
            Node::Leaf(mut leaf_node) => {
                let split_result = leaf_node.add_and_split_if_full(value);
                self.update_file_block(node_offset, leaf_node.bytes())?;
                Ok(split_result)
            }
            Node::Internal(mut internal_node) => {
                let child_offset = internal_node.child_offset_of_value(value);

                let AddAndSplitResult::Splited {
                    right_node_offset,
                    key,
                } = self.add_and_split_if_full(child_offset, value)?
                else {
                    return Ok(AddAndSplitResult::NotSplited);
                };

                let split_result = internal_node.add_and_split_if_full(right_node_offset, key);
                self.update_file_block(node_offset, internal_node.bytes())?;

                Ok(split_result)
            }
        }
    }
    fn has(&self, value: u128) -> std::io::Result<bool> {
        let mut node = self.root_node()?;
        loop {
            match node {
                Node::Internal(internal_node) => {
                    let offset = internal_node.child_offset_of_value(value);
                    node = self.node_from_offset(offset)?;
                }
                Node::Leaf(leaf_node) => {
                    return Ok(leaf_node.has(value));
                }
            }
        }
    }
    fn root_node(&self) -> std::io::Result<Node> {
        let header = self.read_header()?;
        self.node_from_offset(header.root_node_offset)
    }
    fn node_from_offset(&self, offset: u64) -> std::io::Result<Node> {
        let bytes = self.read_block(offset)?;
        match bytes[0] {
            0 => Ok(Node::Leaf(LeafNode::from_bytes(&bytes))),
            1 => Ok(Node::Internal(InternalNode::from_bytes(&bytes))),
            _ => unreachable!(),
        }
    }
    fn read_header(&self) -> std::io::Result<Header> {
        let bytes = self.read_block(0)?;
        Ok(Header::from_bytes(&bytes))
    }
    fn read_block(&self, offset: u64) -> std::io::Result<[u8; 4096]> {
        let mut buf = [0; 4096];
        let bytes_read = unsafe {
            libc::pread(
                self.file.as_raw_fd(),
                buf.as_mut_ptr() as _,
                4096,
                (offset * 4096) as _,
            )
        };
        if bytes_read < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if (bytes_read as usize) < buf.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to read block {offset}, expected 4096 bytes, got {bytes_read}"),
            ));
        }

        Ok(buf)
    }
}

enum AddAndSplitResult {
    Splited { right_node_offset: u64, key: u128 },
    NotSplited,
}

struct Header {
    root_node_offset: u64,
}

impl Header {
    fn from_bytes(bytes: &[u8; 4096]) -> Self {
        let root_node_offset = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        Self { root_node_offset }
    }
}

enum Node {
    Leaf(LeafNode),
    Internal(InternalNode),
}

struct LeafNode {
    prev_node_offset: Option<u64>,
    next_node_offset: Option<u64>,
    len: usize,
    values: [u128; 254],
}

impl LeafNode {
    fn from_bytes(bytes: &[u8; 4096]) -> Self {
        let prev_node_offset = {
            let value = u64::from_le_bytes(bytes[1..9].try_into().unwrap());
            if value == 0 { None } else { Some(value) }
        };
        let next_node_offset = {
            let value = u64::from_le_bytes(bytes[9..17].try_into().unwrap());
            if value == 0 { None } else { Some(value) }
        };
        let len = bytes[17] as usize;
        let mut values = [0; 254];
        for i in 0..len {
            let index = 18 + i * 16;
            values[i] = u128::from_le_bytes(bytes[index..index + 16].try_into().unwrap());
        }
        Self {
            prev_node_offset,
            next_node_offset,
            len,
            values,
        }
    }
    fn has(&self, value: u128) -> bool {
        for i in 0..self.len {
            if self.values[i] == value {
                return true;
            }
        }
        false
    }
}

struct InternalNode {
    key_len: usize,
    keys: [u128; 170],
    node_offsets: [u64; 171],
}

impl InternalNode {
    fn from_bytes(bytes: &[u8; 4096]) -> Self {
        let key_len = bytes[1] as usize;
        let mut keys = [0; 170];
        for i in 0..key_len {
            let index = 2 + i * 16;
            keys[i] = u128::from_le_bytes(bytes[index..index + 16].try_into().unwrap());
        }
        let mut node_offsets = [0; 171];
        if key_len > 0 {
            for i in 0..key_len + 1 {
                let index = 2 + 16 * 170 + i * 8;
                node_offsets[i] = u64::from_le_bytes(bytes[index..index + 8].try_into().unwrap());
            }
        }

        Self {
            key_len,
            keys,
            node_offsets,
        }
    }
    fn child_offset_of_value(&self, value: u128) -> u64 {
        for i in 0..self.key_len {
            if self.keys[i] < value {
                return self.node_offsets[i];
            }
        }
        self.node_offsets[self.key_len]
    }
}

fn main() {
    let mut set = BPTreeSet::new().unwrap();
    set.add(10203040);
    println!(
        "has 10203040? expected true, actual {}",
        set.has(10203040).unwrap()
    );
    println!(
        "has 12345678? expected false, actual {}",
        set.has(12345678).unwrap()
    );
}
