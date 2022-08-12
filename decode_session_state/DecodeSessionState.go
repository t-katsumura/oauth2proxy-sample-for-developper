package main

import (
	"bytes"
	"time"
	"C"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"github.com/pierrec/lz4"
	"github.com/vmihailenco/msgpack/v4"
)


// SessionState is used to store information about the currently authenticated user session
type SessionState struct {
	CreatedAt *time.Time `msgpack:"ca,omitempty"`
	ExpiresOn *time.Time `msgpack:"eo,omitempty"`

	AccessToken  string `msgpack:"at,omitempty"`
	IDToken      string `msgpack:"it,omitempty"`
	RefreshToken string `msgpack:"rt,omitempty"`

	Nonce []byte `msgpack:"n,omitempty"`

	Email             string   `msgpack:"e,omitempty"`
	User              string   `msgpack:"u,omitempty"`
	Groups            []string `msgpack:"g,omitempty"`
	PreferredUsername string   `msgpack:"pu,omitempty"`

	// Internal helpers, not serialized
	// Clock clock.Clock `msgpack:"-"`
	// Lock  Lock        `msgpack:"-"`
}


// Cipher provides methods to encrypt and decrypt
type Cipher interface {
	Encrypt(value []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

type cfbCipher struct {
	cipher.Block
}

// NewCFBCipher returns a new AES CFB Cipher
func NewCFBCipher(secret []byte) (Cipher, error) {
	c, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}
	return &cfbCipher{Block: c}, err
}

// Encrypt with AES CFB
func (c *cfbCipher) Encrypt(value []byte) ([]byte, error) {
	ciphertext := make([]byte, aes.BlockSize+len(value))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to create initialization vector %s", err)
	}

	stream := cipher.NewCFBEncrypter(c.Block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], value)
	return ciphertext, nil
}

// Decrypt an AES CFB ciphertext
func (c *cfbCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("encrypted value should be at least %d bytes, but is only %d bytes", aes.BlockSize, len(ciphertext))
	}

	iv, ciphertext := ciphertext[:aes.BlockSize], ciphertext[aes.BlockSize:]
	plaintext := make([]byte, len(ciphertext))
	stream := cipher.NewCFBDecrypter(c.Block, iv)
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

// lz4Compress compresses with LZ4
//
// The Compress:Decompress ratio is 1:Many. LZ4 gives fastest decompress speeds
// at the expense of greater compression compared to other compression
// algorithms.
func lz4Compress(payload []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	zw := lz4.NewWriter(nil)
	zw.Header = lz4.Header{
		BlockMaxSize:     65536,
		CompressionLevel: 0,
	}
	zw.Reset(buf)

	reader := bytes.NewReader(payload)
	_, err := io.Copy(zw, reader)
	if err != nil {
		return nil, fmt.Errorf("error copying lz4 stream to buffer: %w", err)
	}
	err = zw.Close()
	if err != nil {
		return nil, fmt.Errorf("error closing lz4 writer: %w", err)
	}

	compressed, err := ioutil.ReadAll(buf)
	if err != nil {
		return nil, fmt.Errorf("error reading lz4 buffer: %w", err)
	}

	return compressed, nil
}

// lz4Decompress decompresses with LZ4
func lz4Decompress(compressed []byte) ([]byte, error) {
	reader := bytes.NewReader(compressed)
	buf := new(bytes.Buffer)
	zr := lz4.NewReader(nil)
	zr.Reset(reader)
	_, err := io.Copy(buf, zr)
	if err != nil {
		return nil, fmt.Errorf("error copying lz4 stream to buffer: %w", err)
	}

	payload, err := ioutil.ReadAll(buf)
	if err != nil {
		return nil, fmt.Errorf("error reading lz4 buffer: %w", err)
	}

	return payload, nil
}

// EncodeSessionState returns an encrypted, lz4 compressed, MessagePack encoded session
func (s *SessionState) EncodeSessionState(c Cipher, compress bool) ([]byte, error) {
	packed, err := msgpack.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("error marshalling session state to msgpack: %w", err)
	}

	if !compress {
		return c.Encrypt(packed)
	}

	compressed, err := lz4Compress(packed)
	if err != nil {
		return nil, err
	}

	return c.Encrypt(compressed)
}

// DecodeSessionState decodes a LZ4 compressed MessagePack into a Session State
func DecodeSessionState(data []byte, c Cipher, compressed bool) (*SessionState, error) {
	decrypted, err := c.Decrypt(data)
	// fmt.Println(decrypted)
	if err != nil {
		return nil, fmt.Errorf("error decrypting the session state: %w", err)
	}

	packed := decrypted
	if compressed {
		packed, err = lz4Decompress(decrypted)
		// fmt.Println(packed)
		if err != nil {
			return nil, err
		}
	}

	var ss SessionState
	err = msgpack.Unmarshal(packed, &ss)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling data to session state: %w", err)
	}

	return &ss, nil
}


//export decode_state
func decode_state(secret *C.char, encoded *C.char) *C.char {

	// const secret = "1234567890123456"
	cfb, _ :=  NewCFBCipher([]byte(C.GoString(secret)))

	// const encoded = "KgfjpsgBTLRKXpBu8lru08_kRKkBSHSReXcFBOi6ORVLtZhtMXffrIcdqHBxcbXFr3_nJL8SgXM2iuvf8EeqqkSWExD7-PNvIQFr2HPoXxMLqTeCWAbi5eBDjeU99oYLU_QksBY3IMHWPZzHjHgRD7LU63ay4Ldcc1W5_oWIYqhJoKBOCSJPTxbiTzJfUuA-fHkAs8IWlKfN8D7Qb_8TK8Dc3jHfFRobJ2MkAYN2HesL_SE2naNwXMrcCp12aVFUaPSL5WmX-zrKpDaIq8tgVC4jNZ2hmw7pD5VS33fkgir67ZHSic-_HEknRvNZl64rm5paA6nZJaQPa6pVegbo8o8IYX9kb2HP4NeAvBOkF9r9_t6NTA0ej0SO1Y9SpkgWc1hhdLgFs9PTdRgdjfOytNaJcTrMLUWGB7SeEUHgRgFEV5g43Ct_ysNIdn8pRZOkiq6DtcpwUdUtxvEHDNHUSW0q6T6OzsWINPdRd8FHqJ4RzTukKQDv4ik2ke8U5Kp_jIYK7Kd_nM90BXczp3oFoLx1Uo6HKJ3B4srDrVLEcgk3KmxagibWWCokrb1jNxXwv8qJ2pVrYQYAqkRkbLM7zcXiXuG0N6VfZCLnw_9t-h3ry-xhF6CdDKTFeVkJXMYxxO9JwIAT0ERD73TGD12zCis_SAbUUKmSkZqs0eUNufxOp9RIkmGRaP9WtJQdQ6yu4QTxFntglAlOf3tkBKj9Au5nfUnZafS4P1T8v5vBoTSTE1yvMcv3IX_hWY8h27zV6lYOxGFibRPDfcirDnwkBikzi37bxBuZqYhpD3ECWfby0RbLrzicRoaJ1P--mlkq57IvjsBKauyPOEjw9O1lcJ_WQL2T2JmKBJNS3RkxwfvjPV4dviXUYzVpeFLvYZYf2IQdmxuTmCk6snazALAwob3TZiXOKAO7eo_Z1H1crSf8jkQ7LDJNFUXMEKL51hYyvsOd562D1DQF5e90OJNkWqA-U1xA5T9Oq4CFH7i4Qje8TTrcPSnpePHAxPnI7BAgJxA9iHCEDj6P0Wcj7M9f2CrXPCMRXGjep9vM66ticYMO0IqzQfG8iZHhLZ26Nzq-WZYEJcITvgkmPVM8kGFSGDvP3kUpS-dxL6fTQcZiannrB3kHOJcJRLczNjCMJlTv7k1_SBaoFs_6WB4lyLGDJ-LgpTVg9hh1n7qyd-tFNtTudC-rsh9p4NjYEtUzmPocKEEmKcPaV4l68gxnNjctA2UyIpMHa_6vG7jSe0dFdxYzasPQsx-Ip4w6W7J6NP1NGPUSE7c3rJON-8PcYXDtRD5XOnu-NZvzcoIq8BBNEGy3jsVmlo6F27dV1bUp1w1s1cF5cjSaTZPy5ocEH_IWPbAvmhs5_sCGFakEN8eGoOhp0N04K47dwr6enFTLT8WrvtyzK7r7CPaI1m9s3WGSSkQJGQYL8deLFM2cJ9FRRpW0_Wzt_PyRnE4NT567t418qiNrjerbhmHfVQ92h5f1lv_9-wcF_m93xAWYXwv-jTWXXMSnizZYoYu7F-vJgcRhYrp545Foa-7e7Wzr-lYwZN8m4Sx8APmJKPxFxqRr8RJEQpXwqolnBJlaZ90gbNEKS03cGS-tfPvcDu3dAn4mxN8Z_9fzc0sGJKjAhlyP5xH4qDd0hzrQyhyPJakw6RguXXDTtBnor759K4mJemeoMTM1gtRuPVcNzOuCRdTKefo_MeLpJOLRxMef0GZZ1cSbq8lE5vY5VAUQXFSSwyrgVpfAXaPCPu4x0FY1fFAXB5SrRdz3CC_ILaYc8z7pv5n7bsTJ6tePxo4VEwl9NAY2VQhm6bTs33_M7hCOvCMbiUNCgwd1i6-dZRaWEERurCStVbHkKsfOsGWA41sKjRyaJ6fCl6D9-NgD37KQs6cL84_1uEgCWal8CwOJ5Ux7bNGA-yrHVbYfSLhqZFxbUhMG-Gp9n6kz-dHkmszsTDVfHasPal4Fzwtxipf8soohSL51hSqBjK63ouTIsqVCqCqak4p_tBYIT1l8IJgrYvJXX5uBEei7SaKxUW5Y8wMM26I_3TDRUU-F7SKyb7qhHXJd2FhryAsleg7TlneKwkxcNzHq0KQ4SZAAl84d53cZDkR1yR-TcIA7SA4-YkrgXafnpJPI2DF2-Zcnd-E8O4muNJVr_OPPPMpmgJQvE5dC-hy9ut99ILQTUzmE3y9L3Y6YmJzup8GdRmJOVpU0SWxlwMWp0_RtmbXtQurmtP0NKrrGKb7WsiI8-QFO8Pwr53_CF8P7pOW_pO4FeQAqQyUsogJugYnaMG7tiO__SIeSxd3lI8A9cvrhpRw4krdxxlKScZBPPzEM8vJV-KMxqkbSCgv0B92qOP2KbT1PNCxwY-5Z45RdYGR0KG0v7TaZlu7AgtrBM8HMAGCd895TXJDMTpxQLdQ8vErbTIbBLZkqxZtJdiEceS6vj3ZNKhOCRBBPCvxzQfmZUXwf2d9Zcvj-LRNQFFNPxGLBYpj6oT0LzPFf9RaxUG64tZqvrqkdsKTtB2ry2Mndju3jRWRhkUr-XJyDStxcJ195XEDa4Wi3_STgJasLoMyWa-c16pXCnVUq9G2X6gN7G8p2c34vpn-yYlceHCKinvN5FKKvI8bzCfinnefeKmPaL3iBIjaNRIUVNqoFFWXdnnSKHwGTGa3nAIG02z3VfAKRx4PC-WN0KJcL9AmwJXDnccv-1yygrisJtiBZwIq-7H9t1_x0zytTn7-_LF281Dp_M8Qgru5x7WFZnIiCCz7GCxyKMg5V35Q86TR4oreWfAXHBx8e8yXaiDvI8SPWJl8rlM77nULAxTfJaxB5JP4Lq3a6cowiJT3tKF-MTNBnwHqtGVAmsuh1pbxg4EY2XEF1P8jooTgxztgYYqd2DUDNJOa8YTGv_VP10OUOPYEEBSAHR49QQs5YDd2mjUtn31NndyWbYBTtCpn5rOR7D6BS038IskG2UdBIlo-Hu6Qgk1opG1LZ9KvhgELp1gX2u3rmGNsEIJuECBp3rJq2PmOgMpAqQsqo9phCxHiGEROC9onyhleuA19R9J6AYiB2uPBRN7XLkUX5JZlSSR85V-MXRVoiCZjAyhJXcMSA5ZgcfEjz5MvhY6ZtD4dAuVbhhVQJOSDqW82iTeJ3wMG04tDFEblVHp0s6T7uetbPhmkbPunghoPC8uGgJWKWyte-WYUKOCaJC_BXtgJR9WD8xMheIyYAWi17NmX-FV0r64tGZSXn7_TgdE_n8P6PAEjMQJXWQs_VAee3T18Ep7sdPW4sgsq6v8IkgE7E95bP1VnOptKLRdq085IJaGc6nUUiFKW1sxpZEzfUIuTHO2YDS8-ur4EFD7Ee_gjsG5V0yHfpeg=="
	decoded, _ := base64.URLEncoding.DecodeString(C.GoString(encoded))
	session, _ := DecodeSessionState(decoded, cfb, true)
	str := fmt.Sprintf("%+v", session)
	return C.CString(str)
}


func encode_state() {

	const secret = "1234567890123456"
	cfb, _ :=  NewCFBCipher([]byte(secret))

	const encoded = "KgfjpsgBTLRKXpBu8lru08_kRKkBSHSReXcFBOi6ORVLtZhtMXffrIcdqHBxcbXFr3_nJL8SgXM2iuvf8EeqqkSWExD7-PNvIQFr2HPoXxMLqTeCWAbi5eBDjeU99oYLU_QksBY3IMHWPZzHjHgRD7LU63ay4Ldcc1W5_oWIYqhJoKBOCSJPTxbiTzJfUuA-fHkAs8IWlKfN8D7Qb_8TK8Dc3jHfFRobJ2MkAYN2HesL_SE2naNwXMrcCp12aVFUaPSL5WmX-zrKpDaIq8tgVC4jNZ2hmw7pD5VS33fkgir67ZHSic-_HEknRvNZl64rm5paA6nZJaQPa6pVegbo8o8IYX9kb2HP4NeAvBOkF9r9_t6NTA0ej0SO1Y9SpkgWc1hhdLgFs9PTdRgdjfOytNaJcTrMLUWGB7SeEUHgRgFEV5g43Ct_ysNIdn8pRZOkiq6DtcpwUdUtxvEHDNHUSW0q6T6OzsWINPdRd8FHqJ4RzTukKQDv4ik2ke8U5Kp_jIYK7Kd_nM90BXczp3oFoLx1Uo6HKJ3B4srDrVLEcgk3KmxagibWWCokrb1jNxXwv8qJ2pVrYQYAqkRkbLM7zcXiXuG0N6VfZCLnw_9t-h3ry-xhF6CdDKTFeVkJXMYxxO9JwIAT0ERD73TGD12zCis_SAbUUKmSkZqs0eUNufxOp9RIkmGRaP9WtJQdQ6yu4QTxFntglAlOf3tkBKj9Au5nfUnZafS4P1T8v5vBoTSTE1yvMcv3IX_hWY8h27zV6lYOxGFibRPDfcirDnwkBikzi37bxBuZqYhpD3ECWfby0RbLrzicRoaJ1P--mlkq57IvjsBKauyPOEjw9O1lcJ_WQL2T2JmKBJNS3RkxwfvjPV4dviXUYzVpeFLvYZYf2IQdmxuTmCk6snazALAwob3TZiXOKAO7eo_Z1H1crSf8jkQ7LDJNFUXMEKL51hYyvsOd562D1DQF5e90OJNkWqA-U1xA5T9Oq4CFH7i4Qje8TTrcPSnpePHAxPnI7BAgJxA9iHCEDj6P0Wcj7M9f2CrXPCMRXGjep9vM66ticYMO0IqzQfG8iZHhLZ26Nzq-WZYEJcITvgkmPVM8kGFSGDvP3kUpS-dxL6fTQcZiannrB3kHOJcJRLczNjCMJlTv7k1_SBaoFs_6WB4lyLGDJ-LgpTVg9hh1n7qyd-tFNtTudC-rsh9p4NjYEtUzmPocKEEmKcPaV4l68gxnNjctA2UyIpMHa_6vG7jSe0dFdxYzasPQsx-Ip4w6W7J6NP1NGPUSE7c3rJON-8PcYXDtRD5XOnu-NZvzcoIq8BBNEGy3jsVmlo6F27dV1bUp1w1s1cF5cjSaTZPy5ocEH_IWPbAvmhs5_sCGFakEN8eGoOhp0N04K47dwr6enFTLT8WrvtyzK7r7CPaI1m9s3WGSSkQJGQYL8deLFM2cJ9FRRpW0_Wzt_PyRnE4NT567t418qiNrjerbhmHfVQ92h5f1lv_9-wcF_m93xAWYXwv-jTWXXMSnizZYoYu7F-vJgcRhYrp545Foa-7e7Wzr-lYwZN8m4Sx8APmJKPxFxqRr8RJEQpXwqolnBJlaZ90gbNEKS03cGS-tfPvcDu3dAn4mxN8Z_9fzc0sGJKjAhlyP5xH4qDd0hzrQyhyPJakw6RguXXDTtBnor759K4mJemeoMTM1gtRuPVcNzOuCRdTKefo_MeLpJOLRxMef0GZZ1cSbq8lE5vY5VAUQXFSSwyrgVpfAXaPCPu4x0FY1fFAXB5SrRdz3CC_ILaYc8z7pv5n7bsTJ6tePxo4VEwl9NAY2VQhm6bTs33_M7hCOvCMbiUNCgwd1i6-dZRaWEERurCStVbHkKsfOsGWA41sKjRyaJ6fCl6D9-NgD37KQs6cL84_1uEgCWal8CwOJ5Ux7bNGA-yrHVbYfSLhqZFxbUhMG-Gp9n6kz-dHkmszsTDVfHasPal4Fzwtxipf8soohSL51hSqBjK63ouTIsqVCqCqak4p_tBYIT1l8IJgrYvJXX5uBEei7SaKxUW5Y8wMM26I_3TDRUU-F7SKyb7qhHXJd2FhryAsleg7TlneKwkxcNzHq0KQ4SZAAl84d53cZDkR1yR-TcIA7SA4-YkrgXafnpJPI2DF2-Zcnd-E8O4muNJVr_OPPPMpmgJQvE5dC-hy9ut99ILQTUzmE3y9L3Y6YmJzup8GdRmJOVpU0SWxlwMWp0_RtmbXtQurmtP0NKrrGKb7WsiI8-QFO8Pwr53_CF8P7pOW_pO4FeQAqQyUsogJugYnaMG7tiO__SIeSxd3lI8A9cvrhpRw4krdxxlKScZBPPzEM8vJV-KMxqkbSCgv0B92qOP2KbT1PNCxwY-5Z45RdYGR0KG0v7TaZlu7AgtrBM8HMAGCd895TXJDMTpxQLdQ8vErbTIbBLZkqxZtJdiEceS6vj3ZNKhOCRBBPCvxzQfmZUXwf2d9Zcvj-LRNQFFNPxGLBYpj6oT0LzPFf9RaxUG64tZqvrqkdsKTtB2ry2Mndju3jRWRhkUr-XJyDStxcJ195XEDa4Wi3_STgJasLoMyWa-c16pXCnVUq9G2X6gN7G8p2c34vpn-yYlceHCKinvN5FKKvI8bzCfinnefeKmPaL3iBIjaNRIUVNqoFFWXdnnSKHwGTGa3nAIG02z3VfAKRx4PC-WN0KJcL9AmwJXDnccv-1yygrisJtiBZwIq-7H9t1_x0zytTn7-_LF281Dp_M8Qgru5x7WFZnIiCCz7GCxyKMg5V35Q86TR4oreWfAXHBx8e8yXaiDvI8SPWJl8rlM77nULAxTfJaxB5JP4Lq3a6cowiJT3tKF-MTNBnwHqtGVAmsuh1pbxg4EY2XEF1P8jooTgxztgYYqd2DUDNJOa8YTGv_VP10OUOPYEEBSAHR49QQs5YDd2mjUtn31NndyWbYBTtCpn5rOR7D6BS038IskG2UdBIlo-Hu6Qgk1opG1LZ9KvhgELp1gX2u3rmGNsEIJuECBp3rJq2PmOgMpAqQsqo9phCxHiGEROC9onyhleuA19R9J6AYiB2uPBRN7XLkUX5JZlSSR85V-MXRVoiCZjAyhJXcMSA5ZgcfEjz5MvhY6ZtD4dAuVbhhVQJOSDqW82iTeJ3wMG04tDFEblVHp0s6T7uetbPhmkbPunghoPC8uGgJWKWyte-WYUKOCaJC_BXtgJR9WD8xMheIyYAWi17NmX-FV0r64tGZSXn7_TgdE_n8P6PAEjMQJXWQs_VAee3T18Ep7sdPW4sgsq6v8IkgE7E95bP1VnOptKLRdq085IJaGc6nUUiFKW1sxpZEzfUIuTHO2YDS8-ur4EFD7Ee_gjsG5V0yHfpeg=="
	decoded, _ := base64.URLEncoding.DecodeString(encoded)
	session, _ := DecodeSessionState(decoded, cfb, true)

	re_encoded, _ := session.EncodeSessionState(cfb, true)
	str := base64.RawURLEncoding.EncodeToString(re_encoded)
	fmt.Println(str)
}

func main() {
	encode_state()
}