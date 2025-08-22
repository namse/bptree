use std::os::fd::AsRawFd;

struct BPTreeSet {
    file: std::fs::File,
}

impl BPTreeSet {
    fn new() -> std::io::Result<Self> {
        let mut set = BPTreeSet {
            file: std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .open("./bptree")?,
        };
        let root_node = LeafNode::new(vec![]);
        set.write_block(4096, &root_node.to_bytes())?;
        set.write_header(Header {
            root_node_offset: 4096,
            next_node_offset: 8192,
        })?;
        Ok(set)
    }
    fn add(&mut self, value: u128) -> std::io::Result<()> {
        let root_node_offset = self.root_node_offset()?;
        let Some((new_child_key, new_child_node_offset)) =
            self.add_recursive(value, root_node_offset)?
        else {
            return Ok(());
        };

        let new_root_node =
            InternalNode::new(root_node_offset, new_child_node_offset, new_child_key);
        let new_root_offset = self.push_new_node(&Node::Internal(new_root_node))?;

        self.update_root_node_offset(new_root_offset)?;
        Ok(())
    }

    fn add_recursive(
        &mut self,
        value: u128,
        node_offset: u64,
    ) -> std::io::Result<Option<(u128, u64)>> {
        let mut node = self.node_from_offset(node_offset)?;
        let splitted = match &mut node {
            Node::Internal(internal_node) => {
                let child_offset = internal_node.child_offset_of_value(value);
                let Some((new_child_key, new_child_node_offset)) =
                    self.add_recursive(value, child_offset)?
                else {
                    return Ok(None);
                };

                internal_node
                    .add_and_split_if_full(new_child_node_offset, new_child_key)
                    .map(|(right_node, key)| (Node::Internal(right_node), key))
            }
            Node::Leaf(leaf_node) => leaf_node
                .add_and_split_if_full(value)
                .map(|(right_node, key)| (Node::Leaf(right_node), key)),
        };

        self.write_block(node_offset, &node.to_bytes())?;

        if let Some((right_node, key)) = splitted {
            let right_node_offset = self.push_new_node(&right_node)?;
            Ok(Some((key, right_node_offset)))
        } else {
            Ok(None)
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
            return Err(std::io::Error::other(format!(
                "Failed to read block {offset}, expected 4096 bytes, got {bytes_read}"
            )));
        }

        Ok(buf)
    }
    fn root_node_offset(&self) -> std::io::Result<u64> {
        let header = self.read_header()?;
        Ok(header.root_node_offset)
    }
    fn update_root_node_offset(&mut self, offset: u64) -> std::io::Result<()> {
        let mut header = self.read_header()?;
        header.root_node_offset = offset;
        self.write_header(header)
    }
    fn write_header(&mut self, header: Header) -> std::io::Result<()> {
        let bytes = header.to_bytes();
        self.write_block(0, &bytes)?;
        Ok(())
    }
    fn write_block(&mut self, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
        let bytes_written = unsafe {
            libc::pwrite(
                self.file.as_raw_fd(),
                bytes.as_ptr() as _,
                bytes.len(),
                (offset * 4096) as _,
            )
        };
        if bytes_written < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
    fn allocate_node_offset(&mut self) -> std::io::Result<u64> {
        let mut header = self.read_header()?;
        let offset = header.next_node_offset;
        header.next_node_offset += 1;
        self.write_header(header)?;
        Ok(offset)
    }
    fn push_new_node(&mut self, node: &Node) -> std::io::Result<u64> {
        let offset = self.allocate_node_offset()?;
        self.write_block(offset, &node.to_bytes())?;
        Ok(offset)
    }
}

struct Header {
    root_node_offset: u64,
    next_node_offset: u64,
}

impl Header {
    fn from_bytes(bytes: &[u8; 4096]) -> Self {
        let root_node_offset = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let next_node_offset = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        Self {
            root_node_offset,
            next_node_offset,
        }
    }

    fn to_bytes(&self) -> [u8; 4096] {
        let mut bytes = [0; 4096];
        bytes[0..8].copy_from_slice(&self.root_node_offset.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.next_node_offset.to_le_bytes());
        bytes
    }
}

enum Node {
    Leaf(LeafNode),
    Internal(InternalNode),
}
impl Node {
    fn to_bytes(&self) -> [u8; 4096] {
        match self {
            Node::Leaf(leaf_node) => leaf_node.to_bytes(),
            Node::Internal(internal_node) => internal_node.to_bytes(),
        }
    }
}

struct LeafNode {
    prev_node_offset: Option<u64>,
    next_node_offset: Option<u64>,
    values: Vec<u128>,
}

impl LeafNode {
    const MAX_VALUES: usize = 254;
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
        let mut values = Vec::with_capacity(len);
        for i in 0..len {
            let index = 18 + i * 16;
            values.push(u128::from_le_bytes(
                bytes[index..index + 16].try_into().unwrap(),
            ));
        }
        Self {
            prev_node_offset,
            next_node_offset,
            values,
        }
    }
    fn to_bytes(&self) -> [u8; 4096] {
        let mut bytes = [0; 4096];
        bytes[1..9].copy_from_slice(&self.prev_node_offset.unwrap_or_default().to_le_bytes());
        bytes[9..17].copy_from_slice(&self.next_node_offset.unwrap_or_default().to_le_bytes());
        bytes[17] = self.values.len() as u8;
        for i in 0..self.values.len() {
            let index = 18 + i * 16;
            bytes[index..index + 16].copy_from_slice(&self.values[i].to_le_bytes());
        }
        bytes
    }
    fn has(&self, value: u128) -> bool {
        self.values.contains(&value)
    }
    fn add_and_split_if_full(&mut self, value: u128) -> Option<(LeafNode, u128)> {
        self.values.push(value);

        if self.values.len() < LeafNode::MAX_VALUES {
            return None;
        }

        self.values.sort();

        let mid = self.values.len() / 2;
        let right = self.values.split_off(mid);
        let right_values_first = right[0];
        let right_node = LeafNode::new(right);

        Some((right_node, right_values_first))
    }
    fn new(values: Vec<u128>) -> Self {
        Self {
            prev_node_offset: None,
            next_node_offset: None,
            values,
        }
    }
}

struct InternalNode {
    keys: Vec<u128>,
    node_offsets: Vec<u64>,
}
impl InternalNode {
    const MAX_KEYS: usize = 170;

    fn from_bytes(bytes: &[u8; 4096]) -> Self {
        let key_len = bytes[1] as usize;
        let mut keys = Vec::with_capacity(key_len);
        for i in 0..key_len {
            let index = 2 + i * 16;
            keys.push(u128::from_le_bytes(
                bytes[index..index + 16].try_into().unwrap(),
            ));
        }
        let mut node_offsets = Vec::with_capacity(key_len + 1);
        if key_len > 0 {
            for i in 0..key_len + 1 {
                let index = 2 + 16 * 170 + i * 8;
                node_offsets.push(u64::from_le_bytes(
                    bytes[index..index + 8].try_into().unwrap(),
                ));
            }
        }

        Self { keys, node_offsets }
    }
    fn to_bytes(&self) -> [u8; 4096] {
        let mut bytes = [0; 4096];
        bytes[1] = self.keys.len() as u8;
        for i in 0..self.keys.len() {
            let index = 2 + i * 16;
            bytes[index..index + 16].copy_from_slice(&self.keys[i].to_le_bytes());
        }
        for i in 0..self.node_offsets.len() {
            let index = 2 + 16 * InternalNode::MAX_KEYS + i * 8;
            bytes[index..index + 8].copy_from_slice(&self.node_offsets[i].to_le_bytes());
        }
        bytes
    }
    fn child_offset_of_value(&self, value: u128) -> u64 {
        for i in 0..self.keys.len() {
            if self.keys[i] < value {
                return self.node_offsets[i];
            }
        }
        self.node_offsets[self.keys.len()]
    }

    fn new(left_node_offset: u64, right_node_offset: u64, key: u128) -> Self {
        Self {
            keys: vec![key],
            node_offsets: vec![left_node_offset, right_node_offset],
        }
    }

    fn add_and_split_if_full(
        &mut self,
        node_offset: u64,
        key: u128,
    ) -> Option<(InternalNode, u128)> {
        let key_index = self
            .keys
            .iter()
            .position(|&k| k > key)
            .unwrap_or(self.keys.len());

        self.keys.insert(key_index, key);
        self.node_offsets.insert(key_index + 1, node_offset);

        if self.keys.len() < InternalNode::MAX_KEYS {
            return None;
        }

        let mid_and_right_keys = self.keys.split_off(self.keys.len() / 2);
        let (mid_key, right_keys) = mid_and_right_keys.split_first().unwrap();

        let right_node_offsets = self.node_offsets.split_off(self.node_offsets.len() / 2);

        assert_eq!(right_keys.len(), right_node_offsets.len() - 1);

        let right_node = InternalNode {
            keys: right_keys.to_vec(),
            node_offsets: right_node_offsets,
        };

        Some((right_node, *mid_key))
    }
}

fn main() {
    let mut set = BPTreeSet::new().unwrap();
    set.add(10203040).unwrap();
    println!(
        "has 10203040? expected true, actual {}",
        set.has(10203040).unwrap()
    );
    println!(
        "has 12345678? expected false, actual {}",
        set.has(12345678).unwrap()
    );
}
