//! The .rsrc Section
//! Resources are indexed by a multiple-level binary-sorted tree structure. 
//! The general design can incorporate 2**31 levels. By convention, however, 
//! Windows uses three levels: Type Name Language 
//! 
//! A series of resource directory tables relates all of the levels in the following way: 
//! Each directory table is followed by a series of directory entries that give the name or identifier (ID) 
//! for that level (Type, Name, or Language level) and an address of either a data description or another directory table. 
//! If the address points to a data description, then the data is a leaf in the tree. 
//! If the address points to another directory table, then that table lists directory entries at the next level down.
//! 
//! A leaf's Type, Name, and Language IDs are determined by the path that is taken through directory tables to reach the leaf. 
//! The first table determines Type ID, the second table (pointed to by the directory entry in the first table) 
//! determines Name ID, and the third table determines Language ID.


#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct ResourceDataDirectory {

}