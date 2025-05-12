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

        let new_root_node = InternalNode::new(root_node_offset, right_node_offset, key);
        let new_root_offset = self.push_new_node(&Node::Internal(new_root_node))?;
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
                let Some((mut right_node, key)) = leaf_node.add_and_split_if_full(value) else {
                    return Ok(AddAndSplitResult::NotSplited);
                };

                right_node.prev_node_offset = Some(node_offset);
                let right_node_offset = self.push_new_node(&Node::Leaf(right_node))?;

                leaf_node.next_node_offset = Some(right_node_offset);
                self.write_block(node_offset, &leaf_node.to_bytes())?;

                Ok(AddAndSplitResult::Splited {
                    right_node_offset,
                    key,
                })
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
                여기 해야하는데, 이거 분명 setAddAndSplitIfFull 타입으로 리턴이 안될거야. 그래서 leaf때처럼 노드 푸시 해야해.
                self.write_block(node_offset, &internal_node.to_bytes())?;

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

enum AddAndSplitResult {
    Splited { right_node_offset: u64, key: u128 },
    NotSplited,
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
    fn to_bytes(&self) -> [u8; 4096] {
        let mut bytes = [0; 4096];
        bytes[1..9].copy_from_slice(&self.prev_node_offset.unwrap().to_le_bytes());
        bytes[9..17].copy_from_slice(&self.next_node_offset.unwrap().to_le_bytes());
        bytes[17] = self.len as u8;
        for i in 0..self.len {
            let index = 18 + i * 16;
            bytes[index..index + 16].copy_from_slice(&self.values[i].to_le_bytes());
        }
        bytes
    }
    fn has(&self, value: u128) -> bool {
        for i in 0..self.len {
            if self.values[i] == value {
                return true;
            }
        }
        false
    }
    fn add_and_split_if_full(&mut self, value: u128) -> Option<(LeafNode, u128)> {
        let is_not_full = self.len != self.values.len();
        if is_not_full {
            self.values[self.len] = value;
            self.len += 1;
            return None;
        }

        let buf = {
            let mut buf = [0; 255];
            buf[0..self.values.len()].copy_from_slice(&self.values);
            buf[self.values.len()] = value;
            buf.sort();
            buf
        };

        let mid = buf.len() / 2;
        let (left, right) = buf.split_at(mid);
        let right_node = LeafNode::new(right);

        self.values[0..mid].copy_from_slice(&left);
        self.len = mid;

        let right_values_first = right[0];

        Some((right_node, right_values_first))
    }
    fn new(init_values: &[u128]) -> Self {
        Self {
            prev_node_offset: None,
            next_node_offset: None,
            len: init_values.len(),
            values: init_values.try_into().unwrap(),
        }
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
    fn to_bytes(&self) -> [u8; 4096] {
        let mut bytes = [0; 4096];
        bytes[1] = self.key_len as u8;
        for i in 0..self.key_len {
            let index = 2 + i * 16;
            bytes[index..index + 16].copy_from_slice(&self.keys[i].to_le_bytes());
        }
        for i in 0..self.key_len + 1 {
            let index = 2 + 16 * 170 + i * 8;
            bytes[index..index + 8].copy_from_slice(&self.node_offsets[i].to_le_bytes());
        }
        bytes
    }
    fn child_offset_of_value(&self, value: u128) -> u64 {
        for i in 0..self.key_len {
            if self.keys[i] < value {
                return self.node_offsets[i];
            }
        }
        self.node_offsets[self.key_len]
    }

    fn new(root_node_offset: u64, new_root_offset: u64, key: u128) -> Self {
        let mut keys = [0; 170];
        keys[0] = key;

        let mut node_offsets = [0; 171];
        node_offsets[0] = root_node_offset;
        node_offsets[1] = new_root_offset;

        Self {
            key_len: 1,
            keys,
            node_offsets,
        }
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
