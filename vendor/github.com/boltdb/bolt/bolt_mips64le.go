// +build mips64le

package bolt

// maxMapSize represents the largest mmap size supported by Bolt.
const maxMapSize = 0xFFFFFFFF // 4GB

// maxAllocSize is the size used when creating array pointers.
const maxAllocSize = 0x7FFFFFFF
