// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.1
// 	protoc        v4.24.4
// source: ebpf/ebpf.proto

package ebpf

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type MonitorBtrfsRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Major uint32 `protobuf:"varint,1,opt,name=major,proto3" json:"major,omitempty"`
	Minor uint32 `protobuf:"varint,2,opt,name=minor,proto3" json:"minor,omitempty"`
}

func (x *MonitorBtrfsRequest) Reset() {
	*x = MonitorBtrfsRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ebpf_ebpf_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MonitorBtrfsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MonitorBtrfsRequest) ProtoMessage() {}

func (x *MonitorBtrfsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_ebpf_ebpf_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MonitorBtrfsRequest.ProtoReflect.Descriptor instead.
func (*MonitorBtrfsRequest) Descriptor() ([]byte, []int) {
	return file_ebpf_ebpf_proto_rawDescGZIP(), []int{0}
}

func (x *MonitorBtrfsRequest) GetMajor() uint32 {
	if x != nil {
		return x.Major
	}
	return 0
}

func (x *MonitorBtrfsRequest) GetMinor() uint32 {
	if x != nil {
		return x.Minor
	}
	return 0
}

type MonitorBtrfsResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Major uint32 `protobuf:"varint,1,opt,name=major,proto3" json:"major,omitempty"`
	Minor uint32 `protobuf:"varint,2,opt,name=minor,proto3" json:"minor,omitempty"`
	Uuid  string `protobuf:"bytes,3,opt,name=uuid,proto3" json:"uuid,omitempty"`
	Ret   int32  `protobuf:"varint,4,opt,name=ret,proto3" json:"ret,omitempty"`
}

func (x *MonitorBtrfsResponse) Reset() {
	*x = MonitorBtrfsResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ebpf_ebpf_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MonitorBtrfsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MonitorBtrfsResponse) ProtoMessage() {}

func (x *MonitorBtrfsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_ebpf_ebpf_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MonitorBtrfsResponse.ProtoReflect.Descriptor instead.
func (*MonitorBtrfsResponse) Descriptor() ([]byte, []int) {
	return file_ebpf_ebpf_proto_rawDescGZIP(), []int{1}
}

func (x *MonitorBtrfsResponse) GetMajor() uint32 {
	if x != nil {
		return x.Major
	}
	return 0
}

func (x *MonitorBtrfsResponse) GetMinor() uint32 {
	if x != nil {
		return x.Minor
	}
	return 0
}

func (x *MonitorBtrfsResponse) GetUuid() string {
	if x != nil {
		return x.Uuid
	}
	return ""
}

func (x *MonitorBtrfsResponse) GetRet() int32 {
	if x != nil {
		return x.Ret
	}
	return 0
}

var File_ebpf_ebpf_proto protoreflect.FileDescriptor

var file_ebpf_ebpf_proto_rawDesc = []byte{
	0x0a, 0x0f, 0x65, 0x62, 0x70, 0x66, 0x2f, 0x65, 0x62, 0x70, 0x66, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x0b, 0x72, 0x65, 0x70, 0x6c, 0x69, 0x74, 0x2e, 0x65, 0x62, 0x70, 0x66, 0x22, 0x41,
	0x0a, 0x13, 0x4d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x42, 0x74, 0x72, 0x66, 0x73, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x6d, 0x61, 0x6a, 0x6f, 0x72, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x6d, 0x61, 0x6a, 0x6f, 0x72, 0x12, 0x14, 0x0a, 0x05, 0x6d,
	0x69, 0x6e, 0x6f, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x6d, 0x69, 0x6e, 0x6f,
	0x72, 0x22, 0x68, 0x0a, 0x14, 0x4d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x42, 0x74, 0x72, 0x66,
	0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x6d, 0x61, 0x6a,
	0x6f, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x6d, 0x61, 0x6a, 0x6f, 0x72, 0x12,
	0x14, 0x0a, 0x05, 0x6d, 0x69, 0x6e, 0x6f, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05,
	0x6d, 0x69, 0x6e, 0x6f, 0x72, 0x12, 0x12, 0x0a, 0x04, 0x75, 0x75, 0x69, 0x64, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x75, 0x75, 0x69, 0x64, 0x12, 0x10, 0x0a, 0x03, 0x72, 0x65, 0x74,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x05, 0x52, 0x03, 0x72, 0x65, 0x74, 0x32, 0x5d, 0x0a, 0x04, 0x45,
	0x62, 0x70, 0x66, 0x12, 0x55, 0x0a, 0x0c, 0x4d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x42, 0x74,
	0x72, 0x66, 0x73, 0x12, 0x20, 0x2e, 0x72, 0x65, 0x70, 0x6c, 0x69, 0x74, 0x2e, 0x65, 0x62, 0x70,
	0x66, 0x2e, 0x4d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x42, 0x74, 0x72, 0x66, 0x73, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x21, 0x2e, 0x72, 0x65, 0x70, 0x6c, 0x69, 0x74, 0x2e, 0x65,
	0x62, 0x70, 0x66, 0x2e, 0x4d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x42, 0x74, 0x72, 0x66, 0x73,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x30, 0x01, 0x42, 0x24, 0x5a, 0x22, 0x67, 0x69,
	0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x72, 0x65, 0x70, 0x6c, 0x69, 0x74, 0x2f,
	0x72, 0x65, 0x70, 0x6c, 0x69, 0x74, 0x2d, 0x65, 0x62, 0x70, 0x66, 0x2f, 0x65, 0x62, 0x70, 0x66,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_ebpf_ebpf_proto_rawDescOnce sync.Once
	file_ebpf_ebpf_proto_rawDescData = file_ebpf_ebpf_proto_rawDesc
)

func file_ebpf_ebpf_proto_rawDescGZIP() []byte {
	file_ebpf_ebpf_proto_rawDescOnce.Do(func() {
		file_ebpf_ebpf_proto_rawDescData = protoimpl.X.CompressGZIP(file_ebpf_ebpf_proto_rawDescData)
	})
	return file_ebpf_ebpf_proto_rawDescData
}

var file_ebpf_ebpf_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_ebpf_ebpf_proto_goTypes = []interface{}{
	(*MonitorBtrfsRequest)(nil),  // 0: replit.ebpf.MonitorBtrfsRequest
	(*MonitorBtrfsResponse)(nil), // 1: replit.ebpf.MonitorBtrfsResponse
}
var file_ebpf_ebpf_proto_depIdxs = []int32{
	0, // 0: replit.ebpf.Ebpf.MonitorBtrfs:input_type -> replit.ebpf.MonitorBtrfsRequest
	1, // 1: replit.ebpf.Ebpf.MonitorBtrfs:output_type -> replit.ebpf.MonitorBtrfsResponse
	1, // [1:2] is the sub-list for method output_type
	0, // [0:1] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_ebpf_ebpf_proto_init() }
func file_ebpf_ebpf_proto_init() {
	if File_ebpf_ebpf_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_ebpf_ebpf_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MonitorBtrfsRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ebpf_ebpf_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MonitorBtrfsResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_ebpf_ebpf_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_ebpf_ebpf_proto_goTypes,
		DependencyIndexes: file_ebpf_ebpf_proto_depIdxs,
		MessageInfos:      file_ebpf_ebpf_proto_msgTypes,
	}.Build()
	File_ebpf_ebpf_proto = out.File
	file_ebpf_ebpf_proto_rawDesc = nil
	file_ebpf_ebpf_proto_goTypes = nil
	file_ebpf_ebpf_proto_depIdxs = nil
}
