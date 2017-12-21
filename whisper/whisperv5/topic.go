// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Contains the Whisper protocol Topic element.

package whisperv5

import (
	"p2pay/common"
	"p2pay/common/hexutil"
)

// Topic represents a cryptographically secure, probabilistic partial
// classifications of a message, determined as the first (left) 4 bytes of the
// SHA3 hash of some arbitrary data given by the original author of the message.
type TopicType [TopicLength]byte

var (
	updateQueryTopic = BytesToTopic([]byte("38eba437f85753b3688490143de92a77f6dc92dfea02002c8fb4e1b41fcc86d8261ac2c720980fdae22cf4ec4f517c47d7729685754ee2883b37db029b237262"))
	updateDataTopic  = BytesToTopic([]byte("47c438df91591edf448d24f1228ba7511f031e807337d3e3a2f4428998e4a4e1b9ad7449d1c47fbe017bbaf0a3e3afa28bed78be1ee6dbe76e04935dbedebadc"))
)

func BytesToTopic(b []byte) (t TopicType) {
	sz := TopicLength
	if x := len(b); x < TopicLength {
		sz = x
	}
	for i := 0; i < sz; i++ {
		t[i] = b[i]
	}
	return t
}

// String converts a topic byte array to a string representation.
func (topic *TopicType) String() string {
	return string(common.ToHex(topic[:]))
}

// MarshalText returns the hex representation of t.
func (t TopicType) MarshalText() ([]byte, error) {
	return hexutil.Bytes(t[:]).MarshalText()
}

// UnmarshalText parses a hex representation to a topic.
func (t *TopicType) UnmarshalText(input []byte) error {
	return hexutil.UnmarshalFixedText("Topic", input, t[:])
}
