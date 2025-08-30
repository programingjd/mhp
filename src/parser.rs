pub(crate) struct Parser<'a> {
    unread: &'a [u8],
}

impl<'a> Parser<'a> {
    pub(crate) fn new(slice: &'a [u8]) -> Self {
        Self { unread: slice }
    }
    pub(crate) fn read<const N: usize>(&mut self) -> Option<&[u8; N]> {
        let (value, remaining) = self.unread.split_at_checked(N)?;
        self.unread = remaining;
        Some(value.try_into().unwrap())
    }
    pub(crate) fn read_slice(&mut self, n: usize) -> Option<&[u8]> {
        let (value, remaining) = self.unread.split_at_checked(n)?;
        self.unread = remaining;
        Some(value)
    }
    pub(crate) fn read_uint(&mut self) -> Option<usize> {
        let (value, remaining) = self.unread.split_at_checked(4)?;
        self.unread = remaining;
        Some(u32::from_le_bytes(value.try_into().unwrap()) as usize)
    }
    pub(crate) fn unread(self) -> &'a [u8] {
        self.unread
    }
}
