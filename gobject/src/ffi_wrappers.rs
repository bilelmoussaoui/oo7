use std::collections::HashMap;

use glib::translate::*;
use gobject_ffi::FfiConvert;

#[derive(Clone, glib::Boxed)]
#[boxed_type(name = "Oo7Attributes")]
pub struct Attributes(pub(crate) HashMap<String, String>);

impl Attributes {
    pub fn into_inner(self) -> HashMap<String, String> {
        self.0
    }
}

impl ToGlibPtr<'_, *mut glib::ffi::GHashTable> for Attributes {
    type Storage = HashMap<String, String>;

    fn to_glib_none(&self) -> Stash<'_, *mut glib::ffi::GHashTable, Self> {
        let ptr = self.0.to_glib_full();
        Stash(ptr, self.0.clone())
    }

    fn to_glib_full(&self) -> *mut glib::ffi::GHashTable {
        self.0.to_glib_full()
    }
}

impl FromGlibPtrNone<*mut glib::ffi::GHashTable> for Attributes {
    unsafe fn from_glib_none(ptr: *mut glib::ffi::GHashTable) -> Self {
        let map = unsafe { HashMap::<String, String>::from_glib_none(ptr) };
        Self(map)
    }
}

impl FfiConvert for Attributes {
    type CType = *mut glib::ffi::GHashTable;

    unsafe fn from_c_borrowed(value: Self::CType) -> Self {
        unsafe { FromGlibPtrNone::from_glib_none(value) }
    }

    fn to_c_owned(self) -> Self::CType {
        ToGlibPtr::to_glib_full(&self)
    }

    fn c_error_value() -> Self::CType {
        std::ptr::null_mut()
    }
}

#[derive(Clone, glib::Boxed)]
#[boxed_type(name = "Oo7ItemVec")]
pub struct ItemVec(pub(crate) std::sync::Arc<Vec<std::sync::Arc<oo7_rs::Item>>>);

impl ToGlibPtr<'_, *mut glib::ffi::GList> for ItemVec {
    type Storage = std::ptr::NonNull<glib::ffi::GList>;

    fn to_glib_none(&self) -> Stash<'_, *mut glib::ffi::GList, Self> {
        let glist = items_vec_to_glist(&self.0);
        Stash(glist, std::ptr::NonNull::new(glist).unwrap())
    }

    fn to_glib_full(&self) -> *mut glib::ffi::GList {
        items_vec_to_glist(&self.0)
    }
}

fn items_vec_to_glist(
    items: &std::sync::Arc<Vec<std::sync::Arc<oo7_rs::Item>>>,
) -> *mut glib::ffi::GList {
    let mut list: *mut glib::ffi::GList = std::ptr::null_mut();
    for item_arc in items.iter() {
        let gobject_item = crate::Item::from_arc(std::sync::Arc::clone(item_arc));
        let ptr: *mut crate::item::ffi::Item = gobject_item.into_glib_ptr();
        unsafe {
            list = glib::ffi::g_list_append(list, ptr as glib::ffi::gpointer);
        }
    }
    list
}

impl FfiConvert for ItemVec {
    type CType = *mut glib::ffi::GList;

    unsafe fn from_c_borrowed(_value: Self::CType) -> Self {
        unimplemented!("ItemVec::from_c_borrowed is not implemented")
    }

    fn to_c_owned(self) -> Self::CType {
        ToGlibPtr::to_glib_full(&self)
    }

    fn c_error_value() -> Self::CType {
        std::ptr::null_mut()
    }
}
