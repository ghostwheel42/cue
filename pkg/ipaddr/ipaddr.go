// Copyright 2023 CUE Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package ipaddr defines IP-related functions.
package ipaddr

import (
	"fmt"
	"math/big"
	"net"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/errors"
	"cuelang.org/go/cue/token"
	"github.com/seancfoley/ipaddress-go/ipaddr"
	"github.com/seancfoley/ipaddress-go/ipaddr/addrstrparam"
)

// parseCIDRs converts cue input value to an IPAddress
func parseCIDR(ip *cue.Value) (a *ipaddr.IPAddress, err error) {
	// the address/network can be represented in various formats supported by ipaddress-go
	// - string
	// - bytes
	// - list of (4 or 16) uint8 values

	var params = new(addrstrparam.IPAddressStringParamsBuilder).AllowEmpty(false).GetIPv4AddressParamsBuilder().Allow_inet_aton_joinedSegments(false).Allow_inet_aton_octal(false).AllowPrefixesBeyondAddressSize(false).GetParentBuilder().ToParams()

	switch ip.Kind() {
	case cue.StringKind:
		s, err := ip.String()
		if err != nil {
			return nil, err
		}
		a, err := ipaddr.NewIPAddressStringParams(s, params).ToAddress()
		if err != nil {
			return nil, err
		}
		return a, nil

	case cue.BytesKind:
		b, err := ip.Bytes()
		if err != nil {
			return nil, err
		}
		a, err := ipaddr.NewIPAddressStringParams(string(b), params).ToAddress()
		if err != nil {
			return nil, err
		}
		return a, nil

	case cue.ListKind:
		iter, err := ip.List()
		if err != nil {
			return nil, err
		}

		var nip net.IP
		for iter.Next() {
			v, err := iter.Value().Int64()
			if err != nil {
				return nil, err
			}
			if v < 0 || v > 255 {
				return nil, errors.Newf(token.NoPos, "invalid byte value (0 <= v <= 255): %d", v)
			}
			nip = append(nip, byte(v))
		}

		a, err := ipaddr.NewIPAddressFromNetIP(nip)
		if err != nil {
			return nil, err
		}
		return a, nil

	}

	return nil, errors.Newf(token.NoPos, "invalid type: %s", ip.Kind())
}

// getSubnet returns a subnet /s at index i from a given prefix c
func getSubnet(c *ipaddr.IPAddress, s int, index *cue.Value) (*ipaddr.IPAddress, error) {
	// c is the prefix the subnet is taken from
	p := c.GetPrefixLen()
	if p == nil {
		return nil, errors.Newf(token.NoPos, "invalid cidr: no prefix length")
	}
	// ignore host bits when getting subnet - is this a good idea?
	c = c.ToPrefixBlock()
	pl := p.Len()
	bc := c.GetBitCount()

	// s is the size of the resulting subnet
	//  > 0: absolute size
	// <= 0: size relative to the prefix length
	if s <= 0 {
		ns := pl - s
		if ns < pl || ns > bc {
			return nil, errors.Newf(token.NoPos, "invalid subnet size (%d <= size <= %d): %d (was %d)", pl, bc, ns, s)
		}
		s = ns
	} else if s < pl || s > bc {
		return nil, errors.Newf(token.NoPos, "invalid subnet size (%d <= size <= %d): %d", pl, bc, s)
	}
	sl := uint(bc - s)

	// calculate maximum index
	maxIdx := big.NewInt(1)
	maxIdx.Lsh(maxIdx, uint(s-pl))
	maxIdx.Sub(maxIdx, big.NewInt(1))

	// index is the index of the resulting subnet
	// number:
	//   < 0: index relative to the end of the source prefix
	//  >= 0: index relative to the start of the source prefix
	// string/bytes:
	//  "-0": the last subnet relative to the start of the source prefix
	//   ...: index represented in various formats supported by ipaddress-go
	var idx *big.Int
	switch index.Kind() {
	case cue.IntKind:
		var err error
		idx, err = index.Int(nil)
		if err != nil {
			return nil, err
		}
	default:
		// try to parse integer passed as string/bytes
		str, err := index.String()
		if err != nil {
			b, err := index.Bytes()
			if err == nil {
				str = string(b)
			}
		}
		if str != "" {
			var okay bool
			idx, okay = new(big.Int).SetString(str, 0)
			if okay {
				// special case: handle "-0"
				if len(idx.Bits()) == 0 && str[0] == '-' {
					idx.Xor(idx, maxIdx)
				}
			} else {
				idx = nil
			}
		}
		// no idx? parse ipaddress-go representations
		if idx == nil {
			ia, err := parseCIDR(index)
			if err != nil {
				return nil, err
			}
			idx = ia.GetLower().GetValue()
			if ia.IsPrefixed() {
				idx = idx.Sub(idx, ia.ToPrefixBlock().GetLower().GetValue())
			}
		}
	}

	// check index boundaries
	if idx.CmpAbs(maxIdx) > 0 {
		return nil, errors.Newf(token.NoPos, "invalid subnet index (abs(index) <= %s): %s", maxIdx, idx)
	}

	// handle negative index
	if idx.Cmp(new(big.Int)) < 0 {
		idx.Neg(idx)
		idx.Xor(idx, maxIdx)
	}

	// shift index to account for result's prefix length
	idx.Lsh(idx, sl)

	// convert index to IPAddress
	var ip *ipaddr.IPAddress
	if c.IsIPv4() {
		ip = ipaddr.NewIPv4AddressFromUint32(uint32(idx.Uint64())).ToIP()
	} else {
		v6, err := ipaddr.NewIPv6AddressFromInt(idx)
		if err != nil {
			return nil, err
		}
		ip = v6.ToIP()
	}

	// prepare result subnet
	r, err := c.AdjustPrefixLenZeroed(s - pl)
	if err != nil {
		return nil, err
	}

	// set host bits to index IPAddress
	r, err = r.BitwiseOr(ip)
	if err != nil {
		return nil, err
	}

	return r, nil
}

// GetSubnet returns a smaller prefix sized "size" at position "index" out of the prefix "cidr"
func GetSubnet(cidr, size, index cue.Value) (string, error) {
	// cidr is the prefix the subnet is taken from
	c, err := parseCIDR(&cidr)
	if err != nil {
		return "", err
	}

	// size is the size of the requested subnet
	s, err := size.Int64()
	if err != nil {
		return "", err
	}
	m := int64(c.GetBitCount())
	if s > m || s < -m {
		return "", errors.Newf(token.NoPos, "invalid subnet size (%d <= d <= %d): %d", -m, m, s)
	}

	// index is the index of the requested subnet
	r, err := getSubnet(c, int(s), &index)
	if err != nil {
		return "", err
	}
	return r.ToCanonicalString(), nil
}

// GetIP returns a single IP address at position "index" out of the prefix "cidr"
func GetIP(cidr, index cue.Value) (string, error) {
	// cidr is the prefix the subnet is taken from
	c, err := parseCIDR(&cidr)
	if err != nil {
		return "", err
	}

	// index is the index of the requested address
	r, err := getSubnet(c, c.GetBitCount(), &index)
	if err != nil {
		return "", err
	}
	return r.WithoutPrefixLen().ToCanonicalString(), nil
}

// GetInterface returns a single IP address at position "index" out of the prefix "cidr" with cidr's prefix length
func GetInterface(cidr, index cue.Value) (string, error) {
	// cidr is the prefix the subnet is taken from
	c, err := parseCIDR(&cidr)
	if err != nil {
		return "", err
	}

	// index is the index of the requested address
	r, err := getSubnet(c, c.GetBitCount(), &index)
	if err != nil {
		return "", err
	}
	return r.SetPrefixLen(c.GetPrefixLen().Len()).ToCanonicalString(), nil
}

// bigInt and ipInfo structs to be used by Info()
type bigInt struct {
	big.Int
}

func (b bigInt) MarshalJSON() ([]byte, error) {
	return []byte(b.String()), nil
}

func (b *bigInt) UnmarshalJSON(p []byte) error {
	s := string(p)
	if s == "null" {
		return nil
	}
	value, okay := new(big.Int).SetString(s, 0)
	if !okay {
		return fmt.Errorf("not a valid big integer: %s", s)
	}
	b.Int = *value
	return nil
}

type ipInfo struct {
	Interface    string  `json:"interface"`
	Address      string  `json:"address"`
	Network      string  `json:"network"`
	Identifier   string  `json:"identifier"`
	PrefixLength int     `json:"prefixlen"`
	Netmask      string  `json:"netmask"`
	Wildcard     string  `json:"wildcard"`
	FirstHost    string  `json:"firsthost"`
	LastHost     string  `json:"lasthost"`
	Broadcast    *string `json:"broadcast,omitempty"`
	IPversion    int     `json:"ipversion"`
	HostPrefix   int     `json:"hostprefix"`
	HostCount    bigInt  `json:"hostcount"`
}

// Info returns some information about "ip" such as prefix length or normalized representation
func Info(ip cue.Value) (*ipInfo, error) {
	c, err := parseCIDR(&ip)
	if err != nil {
		return nil, err
	}

	v := c.GetIPVersion()
	hp := v.GetBitCount()

	pl := hp
	if l := c.GetPrefixLen(); l != nil {
		pl = l.Len()
	}

	nm := c.GetNetworkMask().WithoutPrefixLen().ToCanonicalString()
	wi := c.GetHostMask().WithoutPrefixLen().ToCanonicalString()

	m, err := c.ToMaxHost()
	if err != nil {
		return nil, err
	}

	var fh, lh, bc string
	var bcp *string

	// single host and point-to-point links (RFC 3021 & RFC 6164)
	if pl >= hp-1 {
		fh = c.ToPrefixBlock().WithoutPrefixLen().GetLower().ToCanonicalString()
		lh = fh
		// bc not defined
	} else {
		// "all zero" is network address (v4) or all routers anycast (v6), so first is +1
		fh = c.ToPrefixBlock().Increment(1).WithoutPrefixLen().ToCanonicalString()
		if v == 4 {
			// "all one" is broadcast, so last is -1
			lh = m.Increment(-1).WithoutPrefixLen().ToCanonicalString()
			bc = m.WithoutPrefixLen().ToCanonicalString()
			bcp = &bc
		} else {
			lh = m.Increment(-128).WithoutPrefixLen().ToCanonicalString()
		}
	}

	hc := c.ToPrefixBlock().GetCount()

	res := ipInfo{
		Interface:    c.SetPrefixLen(pl).ToCanonicalString(),
		Address:      c.WithoutPrefixLen().GetLower().ToCanonicalString(),
		Network:      c.ToPrefixBlock().ToCanonicalString(),
		Identifier:   c.ToPrefixBlock().WithoutPrefixLen().GetLower().ToCanonicalString(),
		PrefixLength: pl,
		Netmask:      nm,
		Wildcard:     wi,
		FirstHost:    fh,
		LastHost:     lh,
		Broadcast:    bcp,
		IPversion:    int(v),
		HostPrefix:   hp,
		HostCount:    bigInt{*hc},
	}

	return &res, nil
}

// Type returns an empty string for a non-special CIDR and a non-empty string when it's special
func Type(ip cue.Value) (r string, err error) {
	c, err := parseCIDR(&ip)
	if err != nil {
		return
	}
	// TODO: implement this. Check single addresses and prefixes for "reservedness"
	// Better return a "why" and not a bool, so a string stating why it is reserved.
	// see RFC1918, RFC 3927, etc.

	c.IsUnspecified()
	c.IsAnyLocal()
	c.IsLinkLocal()
	c.IsLoopback()
	c.IsMulticast()
	c.IsUnspecified()
	n := c.GetNetIP()
	n.IsGlobalUnicast()
	n.IsInterfaceLocalMulticast()
	n.IsLinkLocalMulticast()
	n.IsLinkLocalUnicast()
	n.IsLoopback()
	n.IsMulticast()
	n.IsPrivate()
	n.IsUnspecified()

	v := c.GetIPVersion()
	hp := v.GetBitCount()

	pl := hp
	if l := c.GetPrefixLen(); l != nil {
		pl = l.Len()
	}

	r = fmt.Sprintf("TODO: ipv%d %d / %d", v, pl, hp)

	return
}

// IsV4IP returns true if "ip" represents a single valid IPv4 address (without prefix length)
func IsV4IP(ip cue.Value) (r bool, err error) {
	c, err := parseCIDR(&ip)
	if err != nil {
		return
	}
	r = c.IsIPv4() && !c.IsMultiple() && c.GetPrefixLen() == nil
	return
}

// IsV6IP returns true if "ip" represents a single valid IPv6 address (without prefix length)
func IsV6IP(ip cue.Value) (r bool, err error) {
	c, err := parseCIDR(&ip)
	if err != nil {
		return
	}
	r = c.IsIPv6() && !c.IsMultiple() && c.GetPrefixLen() == nil
	return
}

// IsV4CIDR returns true if "ip" represents a valid IPv4 prefix
func IsV4CIDR(ip cue.Value) (r bool, err error) {
	c, err := parseCIDR(&ip)
	if err != nil {
		return
	}
	r = c.IsIPv4() && c.ToPrefixBlock().IsSinglePrefixBlock()
	return
}

// IsV6CIDR returns true if "ip" represents a valid IPv6 prefix
func IsV6CIDR(ip cue.Value) (r bool, err error) {
	c, err := parseCIDR(&ip)
	if err != nil {
		return
	}
	r = c.IsIPv6() && c.ToPrefixBlock().IsSinglePrefixBlock()
	return
}

// IsV4Prefix returns true if "ip" represents a valid IPv4 prefix (host part zero)
func IsV4Prefix(ip cue.Value) (r bool, err error) {
	c, err := parseCIDR(&ip)
	if err != nil {
		return
	}
	r = c.IsIPv4() && c.ToPrefixBlock().IsSinglePrefixBlock() && c.IsMultiple()
	return
}

// IsV6Prefix returns true if "ip" represents a valid IPv6 prefix (host part zero)
func IsV6Prefix(ip cue.Value) (r bool, err error) {
	c, err := parseCIDR(&ip)
	if err != nil {
		return
	}
	r = c.IsIPv6() && c.ToPrefixBlock().IsSinglePrefixBlock() && c.IsMultiple()
	return
}

// IsV4Interface returns true if "ip" represents a valid IPv4 interface
func IsV4Interface(ip cue.Value) (r bool, err error) {
	c, err := parseCIDR(&ip)
	if err != nil {
		return
	}
	if !c.IsPrefixed() || !c.IsIPv4() {
		return
	}
	r = c.ToPrefixBlock().IsSinglePrefixBlock() && !c.IsMultiple()
	if r {
		return
	}
	l := c.GetPrefixLen()
	if l == nil {
		return
	}
	r = l.Len() >= c.GetIPVersion().GetBitCount()-1
	return
}

// IsV6Interface returns true if "ip" represents a valid IPv6 interface
func IsV6Interface(ip cue.Value) (r bool, err error) {
	c, err := parseCIDR(&ip)
	if err != nil {
		return
	}
	if !c.IsPrefixed() || !c.IsIPv6() {
		return
	}
	r = c.ToPrefixBlock().IsSinglePrefixBlock() && !c.IsMultiple()
	if r {
		return
	}
	l := c.GetPrefixLen()
	if l == nil {
		return
	}
	r = l.Len() >= c.GetIPVersion().GetBitCount()-1
	return
}

// IsV4 returns true if "ip" is either a single valid IPv4 address or a valid IPv4 prefix
func IsV4(ip cue.Value) (r bool, err error) {
	c, err := parseCIDR(&ip)
	if err != nil {
		return
	}
	r = c.IsIPv4() && (c.ToPrefixBlock().IsSinglePrefixBlock() || (!c.IsMultiple() && c.GetPrefixLen() == nil))
	return
}

// IsV6 returns true if "ip" is either a single valid IPv6 address or a valid IPv6 prefix
func IsV6(ip cue.Value) (r bool, err error) {
	c, err := parseCIDR(&ip)
	if err != nil {
		return
	}
	r = c.IsIPv6() && (c.ToPrefixBlock().IsSinglePrefixBlock() || (!c.IsMultiple() && c.GetPrefixLen() == nil))
	return
}

// IsIP returns true if "ip" is a single valid IP address (without prefix length)
func IsIP(ip cue.Value) (r bool, err error) {
	c, err := parseCIDR(&ip)
	if err != nil {
		return
	}
	r = !c.IsMultiple() && c.GetPrefixLen() == nil
	return
}

// IsCIDR returns true if "ip" is a valid IP prefix
func IsCIDR(ip cue.Value) (r bool, err error) {
	c, err := parseCIDR(&ip)
	if err != nil {
		return
	}
	if !c.IsPrefixed() {
		return
	}
	r = c.ToPrefixBlock().IsSinglePrefixBlock()
	return
}

// IsPrefix returns true if "ip" is a valid IP prefix (host part zero)
func IsPrefix(ip cue.Value) (r bool, err error) {
	c, err := parseCIDR(&ip)
	if err != nil {
		return
	}
	if !c.IsPrefixed() {
		return
	}
	r = c.ToPrefixBlock().IsSinglePrefixBlock() && c.IsMultiple()
	return
}

// IsInterface returns true if "ip" is a valid IP interface (host part not zero)
func IsInterface(ip cue.Value) (r bool, err error) {
	c, err := parseCIDR(&ip)
	if err != nil {
		return
	}
	if !c.IsPrefixed() {
		return
	}
	r = c.ToPrefixBlock().IsSinglePrefixBlock() && !c.IsMultiple()
	if r {
		return
	}
	l := c.GetPrefixLen()
	if l == nil {
		return
	}
	r = l.Len() >= c.GetIPVersion().GetBitCount()-1
	return
}

// Valid returns true if "ip" is either a single valid IP address or a valid IP prefix
func Valid(ip cue.Value) (r bool, err error) {
	c, err := parseCIDR(&ip)
	if err != nil {
		return
	}
	r = c.ToPrefixBlock().IsSinglePrefixBlock() || (!c.IsMultiple() && c.GetPrefixLen() == nil)
	return
}

// Single returns true if "ip" is just a single valid IP address or a single valid IP prefix
func Single(ip cue.Value) (r bool, err error) {
	c, err := parseCIDR(&ip)
	if err != nil {
		return
	}
	l := c.GetPrefixLen()
	r = l == nil || l.Len() == c.GetIPVersion().GetBitCount()
	return
}

// Range iterates over the individual addresses of the given prefix "cidr"
func Range(cidr cue.Value) ([]string, error) {

	c, err := parseCIDR(&cidr)
	if err != nil {
		return []string{}, err
	}

	m := big.NewInt(0x10000)
	l := c.GetCount()
	if l.Cmp(m) > 0 {
		return []string{}, errors.Newf(token.NoPos, "range too big (count > %s): %s", m, l)
	}

	r := make([]string, 0, l.Int64())
	it := c.WithoutPrefixLen().Iterator()
	for next := it.Next(); next != nil; next = it.Next() {
		r = append(r, next.ToCanonicalString())
	}

	return r, nil
}

// Contains returns true when b is inside a
func Contains(a, b cue.Value) (r bool, err error) {
	ai, err := parseCIDR(&a)
	if err != nil {
		return
	}
	bi, err := parseCIDR(&b)
	if err != nil {
		return
	}
	r = ai.Contains(bi)
	return
}

// Compare returns -1, 0 or +1 comparing a to b. It compares by count first, then by value.
func Compare(a, b cue.Value) (r int, err error) {
	ai, err := parseCIDR(&a)
	if err != nil {
		return
	}
	bi, err := parseCIDR(&b)
	if err != nil {
		return
	}
	r = ai.Compare(bi)
	return
}

// Overlaps returns true when any of the CIDRs given as list overlap with the first CIDR.
func Overlaps(a, b cue.Value) (r bool, err error) {
	ai, err := parseCIDR(&a)
	if err != nil {
		return
	}
	iter, err := b.List()
	if err != nil {
		return false, err
	}
	first := ai.ToSequentialRange()
	var other *ipaddr.IPAddress
	for iter.Next() {
		item := iter.Value()
		other, err = parseCIDR(&item)
		if err != nil {
			return
		}
		if other.ToSequentialRange().Overlaps(first) {
			return true, nil
		}
	}
	return
}

// ToPrefix returns the subnet associated with the prefix length of this address.
func ToPrefix(cidr cue.Value) (r string, err error) {
	c, err := parseCIDR(&cidr)
	if err != nil {
		return
	}
	r = c.ToPrefixBlock().ToCanonicalString()
	return
}

// ToBytes returns the cidr as a list of byte values
func ToBytes(cidr cue.Value) (r []int, err error) {
	c, err := parseCIDR(&cidr)
	if err != nil {
		return
	}
	b := c.Bytes()
	l := len(b)
	r = make([]int, l)
	for i := 0; i < l; i++ {
		r[i] = int(b[i])
	}
	return
}

// PTR returns the PTR to the passed IP address or first address of a CIDR
func PTR(cidr cue.Value) (r string, err error) {
	c, err := parseCIDR(&cidr)
	if err != nil {
		return
	}
	r, err = c.ToPrefixBlock().GetLower().ToReverseDNSString()
	if err != nil {
		return
	}
	return
}
