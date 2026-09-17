use std::collections::HashMap;
use std::sync::Arc;
use windows::Win32::System::Diagnostics::Etw::{
    EVENT_RECORD, TRACE_EVENT_INFO, TdhGetEventInformation,
};
use windows::core::GUID;

pub const IN_UNICODESTRING: u16 = 1;
pub const IN_ANSISTRING: u16 = 2;
pub const IN_INT8: u16 = 3;
pub const IN_UINT8: u16 = 4;
pub const IN_INT16: u16 = 5;
pub const IN_UINT16: u16 = 6;
pub const IN_INT32: u16 = 7;
pub const IN_UINT32: u16 = 8;
pub const IN_INT64: u16 = 9;
pub const IN_UINT64: u16 = 10;
pub const IN_FLOAT: u16 = 11;
pub const IN_DOUBLE: u16 = 12;
pub const IN_BOOLEAN: u16 = 13;
pub const IN_BINARY: u16 = 14;
pub const IN_GUID: u16 = 15;
pub const IN_SID: u16 = 19;
pub const IN_POINTER: u16 = 16;
pub const IN_FILETIME: u16 = 17;
pub const IN_SYSTEMTIME: u16 = 18;
pub const IN_HEXINT32: u16 = 20;
pub const IN_HEXINT64: u16 = 21;

#[derive(Clone)]
pub struct Prop {
    pub name: String,
    pub in_type: u16,
    pub fixed_length: u16,
    pub length_from: Option<usize>,
}

#[derive(Clone)]
pub struct Layout {
    pub props: Vec<Prop>,
    pub usable: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct EventKey {
    pub provider: u128,
    pub id: u16,
    pub version: u8,
}

pub struct SchemaCache {
    map: HashMap<EventKey, Arc<Layout>>,
}

impl Default for SchemaCache {
    fn default() -> Self {
        Self::new()
    }
}

impl SchemaCache {
    pub fn new() -> Self {
        SchemaCache {
            map: HashMap::new(),
        }
    }

    pub fn layout(&mut self, record: &EVENT_RECORD) -> Arc<Layout> {
        let key = EventKey {
            provider: guid_to_u128(&record.EventHeader.ProviderId),
            id: record.EventHeader.EventDescriptor.Id,
            version: record.EventHeader.EventDescriptor.Version,
        };
        self.map.entry(key).or_insert_with(|| Arc::new(fetch(record))).clone()
    }
}

pub fn guid_to_u128(g: &GUID) -> u128 {
    ((g.data1 as u128) << 96)
        | ((g.data2 as u128) << 80)
        | ((g.data3 as u128) << 64)
        | u64::from_be_bytes(g.data4) as u128
}

fn fetch(record: &EVENT_RECORD) -> Layout {
    let mut size = 0u32;
    unsafe {
        let _ = TdhGetEventInformation(record, None, None, &mut size);
    }
    if size == 0 {
        return Layout {
            props: Vec::new(),
            usable: false,
        };
    }
    let mut buf = vec![0u8; size as usize];
    let status = unsafe {
        TdhGetEventInformation(
            record,
            None,
            Some(buf.as_mut_ptr() as *mut TRACE_EVENT_INFO),
            &mut size,
        )
    };
    if status != 0 {
        return Layout {
            props: Vec::new(),
            usable: false,
        };
    }

    unsafe {
        let info = &*(buf.as_ptr() as *const TRACE_EVENT_INFO);
        let count = info.TopLevelPropertyCount as usize;
        let base = buf.as_ptr();
        let props_ptr = std::ptr::addr_of!(info.EventPropertyInfoArray) as *const u8;
        let stride = std::mem::size_of::<
            windows::Win32::System::Diagnostics::Etw::EVENT_PROPERTY_INFO,
        >();
        let mut props = Vec::with_capacity(count);
        let mut usable = true;
        for i in 0..count {
            let p = &*(props_ptr.add(i * stride)
                as *const windows::Win32::System::Diagnostics::Etw::EVENT_PROPERTY_INFO);
            let name_offset = p.NameOffset as usize;
            let name = if name_offset > 0 && name_offset < buf.len() {
                read_wide_at(base.add(name_offset) as *const u16, (buf.len() - name_offset) / 2)
            } else {
                String::new()
            };
            if p.Flags.0 & (0x1 | 0x4) != 0 {
                usable = false;
                break;
            }
            let in_type = p.Anonymous1.nonStructType.InType;
            let (fixed_length, length_from) = if p.Flags.0 & 0x2 != 0 {
                let index = p.Anonymous3.lengthPropertyIndex as usize;
                if index >= i {
                    usable = false;
                    break;
                }
                (0, Some(index))
            } else {
                (p.Anonymous3.length, None)
            };
            props.push(Prop {
                name,
                in_type,
                fixed_length,
                length_from,
            });
        }
        Layout { props, usable }
    }
}

unsafe fn read_wide_at(ptr: *const u16, max: usize) -> String {
    let mut len = 0usize;
    let max = max.min(512);
    unsafe {
        while len < max && *ptr.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
    }
}

pub enum Value {
    U64(u64),
    I64(i64),
    Str(String),
    None,
}

impl Value {
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::U64(v) => Some(*v),
            Value::I64(v) => Some(*v as u64),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }
}

pub struct Decoded<'a> {
    layout: &'a Layout,
    values: Vec<Value>,
}

impl<'a> Decoded<'a> {
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.layout
            .props
            .iter()
            .position(|p| p.name.eq_ignore_ascii_case(name))
            .and_then(|i| self.values.get(i))
    }

    pub fn u64(&self, name: &str) -> Option<u64> {
        self.get(name).and_then(|v| v.as_u64())
    }

    pub fn text(&self, name: &str) -> Option<&str> {
        self.get(name).and_then(|v| v.as_str())
    }
}

pub fn decode<'a>(record: &EVENT_RECORD, layout: &'a Layout) -> Decoded<'a> {
    let mut values = Vec::with_capacity(layout.props.len());
    if !layout.usable || record.UserData.is_null() {
        return Decoded { layout, values };
    }
    let data = record.UserData as *const u8;
    let total = record.UserDataLength as usize;
    let pointer_size = if record.EventHeader.Flags & 0x0020 != 0 {
        4usize
    } else {
        8usize
    };
    let mut offset = 0usize;

    for prop in &layout.props {
        if offset >= total {
            break;
        }
        let remaining = total - offset;
        let fixed_length = match prop.length_from {
            Some(i) => match values.get(i).and_then(|v: &Value| v.as_u64()) {
                Some(n) if n <= u16::MAX as u64 => n as u16,
                _ => break,
            },
            None => prop.fixed_length,
        };
        let (value, consumed) = unsafe {
            read_value(
                data.add(offset),
                remaining,
                prop.in_type,
                fixed_length,
                pointer_size,
            )
        };
        match consumed {
            Some(n) => {
                values.push(value);
                offset += n;
            }
            None => break,
        }
    }
    Decoded { layout, values }
}

unsafe fn read_value(
    ptr: *const u8,
    remaining: usize,
    in_type: u16,
    fixed_length: u16,
    pointer_size: usize,
) -> (Value, Option<usize>) {
    unsafe {
        let need = |n: usize| -> bool { remaining >= n };
        match in_type {
            IN_INT8 | IN_UINT8 => {
                if !need(1) {
                    return (Value::None, None);
                }
                (Value::U64(*ptr as u64), Some(1))
            }
            IN_INT16 | IN_UINT16 => {
                if !need(2) {
                    return (Value::None, None);
                }
                (
                    Value::U64(u16::from_le_bytes([*ptr, *ptr.add(1)]) as u64),
                    Some(2),
                )
            }
            IN_INT32 | IN_UINT32 | IN_HEXINT32 | IN_BOOLEAN | IN_FLOAT => {
                if !need(4) {
                    return (Value::None, None);
                }
                let v = u32::from_le_bytes([*ptr, *ptr.add(1), *ptr.add(2), *ptr.add(3)]);
                (Value::U64(v as u64), Some(4))
            }
            IN_INT64 | IN_UINT64 | IN_HEXINT64 | IN_FILETIME | IN_DOUBLE => {
                if !need(8) {
                    return (Value::None, None);
                }
                let mut b = [0u8; 8];
                std::ptr::copy_nonoverlapping(ptr, b.as_mut_ptr(), 8);
                (Value::U64(u64::from_le_bytes(b)), Some(8))
            }
            IN_POINTER => {
                if !need(pointer_size) {
                    return (Value::None, None);
                }
                let mut b = [0u8; 8];
                std::ptr::copy_nonoverlapping(ptr, b.as_mut_ptr(), pointer_size);
                (Value::U64(u64::from_le_bytes(b)), Some(pointer_size))
            }
            IN_GUID => {
                if !need(16) {
                    return (Value::None, None);
                }
                (Value::None, Some(16))
            }
            IN_SYSTEMTIME => {
                if !need(16) {
                    return (Value::None, None);
                }
                (Value::None, Some(16))
            }
            IN_SID => {
                if !need(8) {
                    return (Value::None, None);
                }
                let sub_count = *ptr.add(1) as usize;
                let size = 8 + sub_count * 4;
                if !need(size) {
                    return (Value::None, None);
                }
                (Value::None, Some(size))
            }
            IN_UNICODESTRING => {
                if fixed_length > 0 {
                    let bytes = fixed_length as usize * 2;
                    if !need(bytes) {
                        return (Value::None, None);
                    }
                    let s = String::from_utf16_lossy(&read_u16s(ptr, fixed_length as usize));
                    return (
                        Value::Str(s.trim_end_matches('\0').to_string()),
                        Some(bytes),
                    );
                }
                let max = remaining / 2;
                let mut len = 0usize;
                while len < max && std::ptr::read_unaligned(ptr.add(len * 2) as *const u16) != 0 {
                    len += 1;
                }
                let s = String::from_utf16_lossy(&read_u16s(ptr, len));
                let consumed = (len + 1).min(max) * 2;
                (Value::Str(s), Some(consumed))
            }
            IN_ANSISTRING => {
                if fixed_length > 0 {
                    let bytes = fixed_length as usize;
                    if !need(bytes) {
                        return (Value::None, None);
                    }
                    let s = String::from_utf8_lossy(std::slice::from_raw_parts(ptr, bytes));
                    return (
                        Value::Str(s.trim_end_matches('\0').to_string()),
                        Some(bytes),
                    );
                }
                let mut len = 0usize;
                while len < remaining && *ptr.add(len) != 0 {
                    len += 1;
                }
                let s = String::from_utf8_lossy(std::slice::from_raw_parts(ptr, len));
                (Value::Str(s.into_owned()), Some((len + 1).min(remaining)))
            }
            IN_BINARY => {
                let n = fixed_length as usize;
                if !need(n) {
                    return (Value::None, None);
                }
                (Value::None, Some(n))
            }
            _ => (Value::None, None),
        }
    }
}

unsafe fn read_u16s(ptr: *const u8, count: usize) -> Vec<u16> {
    unsafe { (0..count).map(|i| std::ptr::read_unaligned(ptr.add(i * 2) as *const u16)).collect() }
}
