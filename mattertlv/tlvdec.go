package mattertlv

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

type ElementType int

const TypeInt ElementType = 1
const TypeBool ElementType = 2
const TypeUTF8String ElementType = 3
const TypeOctetString ElementType = 4
const TypeList ElementType = 5
const TypeNull ElementType = 6

// TlvItem represents one TLV entry.
type TlvItem struct {
	Tag        int
	Type       ElementType
	matterType byte

	valueBool        bool
	valueInt         uint64
	valueString      string
	valueOctetString []byte
	valueList        []TlvItem
}

// GetChild returns slice of all child entries.
func (i TlvItem) GetChild() []TlvItem {
	return i.valueList
}

func (i TlvItem) GetItemWithTag(tag int) *TlvItem {
	for n, item := range i.valueList {
		if item.Tag == tag {
			return &i.valueList[n]
		}
	}
	return nil
}

// GetChild returns value of integer entry as int.
func (i TlvItem) GetInt() int {
	return int(i.valueInt)
}

// GetChild returns value of integer entry as uint64.
func (i TlvItem) GetUint64() uint64 {
	return uint64(i.valueInt)
}
func (i TlvItem) GetOctetString() []byte {
	return i.valueOctetString
}
func (i TlvItem) GetString() string {
	return i.valueString
}
func (i TlvItem) GetBool() bool {
	return i.valueBool
}
func (i TlvItem) Dump(pad int) {
	pads := strings.Repeat("-", pad)
	fmt.Printf(pads)
	fmt.Printf("tag:%3d type:0x%02x itype:", i.Tag, i.matterType)
	switch i.Type {
	case TypeNull:
		fmt.Printf("null\n")
	case TypeInt:
		fmt.Printf("int val:%d\n", i.valueInt)
	case TypeBool:
		fmt.Printf("bool val:%v\n", i.valueBool)
	case TypeUTF8String:
		fmt.Printf("string val:%s\n", i.valueString)
	case TypeOctetString:
		fmt.Printf("bytes val:%s\n", hex.EncodeToString(i.valueOctetString))
	case TypeList:
		fmt.Printf("struct:\n")
		for _, ii := range i.valueList {
			ii.Dump(pad + 2)
		}
		//fmt.Println()
	default:
		fmt.Printf("unknown %d\n", i.Type)
	}
}

func (i TlvItem) DumpToString(buf *strings.Builder, pad int) {
	pads := strings.Repeat(" ", pad)
	buf.WriteString(pads)
	buf.WriteString(fmt.Sprintf("%3d:", i.Tag))
	switch i.Type {
	case TypeNull:
		buf.WriteString("null\n")
	case TypeInt:
		buf.WriteString(fmt.Sprintf("%d\n", i.valueInt))
	case TypeBool:
		buf.WriteString(fmt.Sprintf("%v\n", i.valueBool))
	case TypeUTF8String:
		buf.WriteString(fmt.Sprintf("%s\n", i.valueString))
	case TypeOctetString:
		buf.WriteString(fmt.Sprintf("%s\n", hex.EncodeToString(i.valueOctetString)))
	case TypeList:
		buf.WriteString("struct:\n")
		for _, ii := range i.valueList {
			ii.DumpToString(buf, pad+2)
		}
		//fmt.Println()
	default:
		fmt.Printf("unknown %d\n", i.Type)
	}
}

func (i TlvItem) DumpWithDict(pad int, path string, dictionary map[string]string) {
	path_me := fmt.Sprintf("%s.%d", path, i.Tag)
	pads := strings.Repeat(" ", pad)
	//fmt.Printf("path %s\n", path_me)
	fmt.Printf(pads)
	name, ok := dictionary[path_me]
	if !ok {
		name = fmt.Sprintf("%d", i.Tag)
	}
	fmt.Printf("%s: ", name)
	switch i.Type {
	case TypeNull:
		fmt.Printf("null\n")
	case TypeInt:
		fmt.Printf("%d\n", i.valueInt)
	case TypeBool:
		fmt.Printf("%v\n", i.valueBool)
	case TypeUTF8String:
		fmt.Printf("%s\n", i.valueString)
	case TypeOctetString:
		fmt.Printf("%s\n", hex.EncodeToString(i.valueOctetString))
	case TypeList:
		fmt.Printf("\n")
		for _, ii := range i.valueList {
			ii.DumpWithDict(pad+2, path_me, dictionary)
		}
	default:
		fmt.Printf("unknown %d\n", i.Type)
	}
}

func (i TlvItem) GetItemRec(tag []int) *TlvItem {
	if len(tag) == 0 {
		return &i
	}
	if i.Type == TypeList {
		for _, d := range i.valueList {
			if d.Tag == tag[0] {
				return d.GetItemRec(tag[1:])
			}
		}
	}
	return nil
}

func (i TlvItem) GetOctetStringRec(tag []int) []byte {
	item := i.GetItemRec(tag)
	if item == nil {
		return []byte{}
	} else {
		return item.valueOctetString
	}
}

func (i TlvItem) GetIntRec(tag []int) (uint64, error) {
	item := i.GetItemRec(tag)
	if item == nil {
		return 0, fmt.Errorf("not found")
	} else {
		return item.valueInt, nil
	}
}

func readByte(buf *bytes.Buffer) (int, error) {
	tmp, err := buf.ReadByte()
	if err != nil {
		return 0, fmt.Errorf("truncated TLV: %w", err)
	}
	return int(tmp), nil
}

func readTag(tagctrl byte, item *TlvItem, buf *bytes.Buffer) error {
	if tagctrl == 1 {
		v, err := readByte(buf)
		if err != nil {
			return err
		}
		item.Tag = v
	}
	return nil
}

func decode(buf *bytes.Buffer, container *TlvItem) error {
	for buf.Len() > 0 {
		current := TlvItem{}
		fb, _ := buf.ReadByte()
		tp := fb & 0x1f
		tagctrl := fb >> 5
		current.matterType = tp
		switch tp {
		case 0:
			current.Type = TypeInt
			if err := readTag(tagctrl, &current, buf); err != nil {
				return err
			}
			v, err := readByte(buf)
			if err != nil {
				return err
			}
			current.valueInt = uint64(int8(v))
		case 1:
			current.Type = TypeInt
			if err := readTag(tagctrl, &current, buf); err != nil {
				return err
			}
			var tmp int16
			if err := binary.Read(buf, binary.LittleEndian, &tmp); err != nil {
				return fmt.Errorf("truncated TLV int16: %w", err)
			}
			current.valueInt = uint64(tmp)
		case 2:
			current.Type = TypeInt
			if err := readTag(tagctrl, &current, buf); err != nil {
				return err
			}
			var tmp int32
			if err := binary.Read(buf, binary.LittleEndian, &tmp); err != nil {
				return fmt.Errorf("truncated TLV int32: %w", err)
			}
			current.valueInt = uint64(tmp)
		case 3:
			current.Type = TypeInt
			if err := readTag(tagctrl, &current, buf); err != nil {
				return err
			}
			var tmp int64
			if err := binary.Read(buf, binary.LittleEndian, &tmp); err != nil {
				return fmt.Errorf("truncated TLV int64: %w", err)
			}
			current.valueInt = uint64(tmp)
		case 4:
			current.Type = TypeInt
			if err := readTag(tagctrl, &current, buf); err != nil {
				return err
			}
			v, err := readByte(buf)
			if err != nil {
				return err
			}
			current.valueInt = uint64(v)
		case 5:
			current.Type = TypeInt
			if err := readTag(tagctrl, &current, buf); err != nil {
				return err
			}
			var tmp uint16
			if err := binary.Read(buf, binary.LittleEndian, &tmp); err != nil {
				return fmt.Errorf("truncated TLV uint16: %w", err)
			}
			current.valueInt = uint64(tmp)
		case 6:
			current.Type = TypeInt
			if err := readTag(tagctrl, &current, buf); err != nil {
				return err
			}
			var tmp uint32
			if err := binary.Read(buf, binary.LittleEndian, &tmp); err != nil {
				return fmt.Errorf("truncated TLV uint32: %w", err)
			}
			current.valueInt = uint64(tmp)
		case 7:
			current.Type = TypeInt
			if err := readTag(tagctrl, &current, buf); err != nil {
				return err
			}
			var tmp uint64
			if err := binary.Read(buf, binary.LittleEndian, &tmp); err != nil {
				return fmt.Errorf("truncated TLV uint64: %w", err)
			}
			current.valueInt = uint64(tmp)
		case 8:
			current.Type = TypeBool
			if err := readTag(tagctrl, &current, buf); err != nil {
				return err
			}
			current.valueBool = false
		case 9:
			current.Type = TypeBool
			if err := readTag(tagctrl, &current, buf); err != nil {
				return err
			}
			current.valueBool = true
		case 0xa:
			return fmt.Errorf("unsupported TLV type 0x%x (float)", tp)
		case 0xb:
			return fmt.Errorf("unsupported TLV type 0x%x (double)", tp)
		case 0xc:
			current.Type = TypeUTF8String
			if err := readTag(tagctrl, &current, buf); err != nil {
				return err
			}
			size, err := readByte(buf)
			if err != nil {
				return err
			}
			current.valueOctetString = make([]byte, size)
			buf.Read(current.valueOctetString)
			current.valueString = string(current.valueOctetString)
		case 0x10:
			current.Type = TypeOctetString
			if err := readTag(tagctrl, &current, buf); err != nil {
				return err
			}
			size, err := readByte(buf)
			if err != nil {
				return err
			}
			current.valueOctetString = make([]byte, size)
			buf.Read(current.valueOctetString)
		case 0x11:
			current.Type = TypeOctetString
			if err := readTag(tagctrl, &current, buf); err != nil {
				return err
			}
			var size uint16
			if err := binary.Read(buf, binary.LittleEndian, &size); err != nil {
				return fmt.Errorf("truncated TLV octet string length: %w", err)
			}
			current.valueOctetString = make([]byte, size)
			buf.Read(current.valueOctetString)
		case 0x14:
			current.Type = TypeNull
			if err := readTag(tagctrl, &current, buf); err != nil {
				return err
			}
		case 0x15:
			current.Type = TypeList
			if err := readTag(tagctrl, &current, buf); err != nil {
				return err
			}
			if err := decode(buf, &current); err != nil {
				return err
			}
		case 0x16:
			current.Type = TypeList
			if err := readTag(tagctrl, &current, buf); err != nil {
				return err
			}
			if err := decode(buf, &current); err != nil {
				return err
			}
		case 0x17:
			current.Type = TypeList
			if err := readTag(tagctrl, &current, buf); err != nil {
				return err
			}
			if err := decode(buf, &current); err != nil {
				return err
			}
		case 0x18:
			return nil
		default:
			return fmt.Errorf("unknown TLV type 0x%x", tp)
		}
		container.valueList = append(container.valueList, current)
	}
	return nil
}

// Decode decodes binary TLV into structure represented by TlvItem.
func Decode(in []byte) (TlvItem, error) {
	buf := bytes.NewBuffer(in)
	root := &TlvItem{
		Type: TypeList,
	}
	if err := decode(buf, root); err != nil {
		return TlvItem{}, err
	}
	if len(root.valueList) == 0 {
		return TlvItem{}, fmt.Errorf("empty TLV input")
	}
	return root.valueList[0], nil
}
