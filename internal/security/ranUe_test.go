package security

import (
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"

	"github.com/free5gc/n3iwue/pkg/factory"
	"github.com/free5gc/nas/security"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/milenage"
)

func TestCalculateIpv4HeaderChecksum(t *testing.T) {
	hdr := &ipv4.Header{
		Version:  4,
		Len:      20,
		TOS:      0,
		TotalLen: 84,
		ID:       54321,
		Flags:    ipv4.DontFragment,
		FragOff:  0,
		TTL:      64,
		Protocol: 1, // ICMP
		Src:      net.ParseIP("192.168.1.1"),
		Dst:      net.ParseIP("192.168.1.2"),
	}

	checksum := CalculateIpv4HeaderChecksum(hdr)
	require.NotZero(t, checksum, "Checksum should not be zero")
}

func TestGetAuthSubscription(t *testing.T) {
	k := "465B5CE8B199B49FAA5F0A2EE238A6BC"
	sqn := "000000000020"
	amf := "8000"
	opc := "E8ED289DEBA952E4283B54E88E6183CA"
	op := ""

	authSubs := GetAuthSubscription(k, sqn, amf, opc, op)
	require.Equal(t, k, authSubs.EncPermanentKey)
	require.Equal(t, opc, authSubs.EncOpcKey)
	require.Equal(t, amf, authSubs.AuthenticationManagementField)
	require.Equal(t, sqn, authSubs.SequenceNumber.Sqn)
	require.Equal(t, models.AuthMethod__5_G_AKA, authSubs.AuthenticationMethod)
}

func TestNewRanUeContext(t *testing.T) {
	supi := "imsi-208930000000001"
	ue := NewRanUeContext(supi, 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA1, models.AccessType__3_GPP_ACCESS, "000000000001")

	require.NotNil(t, ue)
	require.Equal(t, supi, ue.Supi)
	require.Equal(t, int64(1), ue.RanUeNgapId)
	require.Equal(t, security.AlgCiphering128NEA0, ue.CipheringAlg)
	require.Equal(t, security.AlgIntegrity128NIA1, ue.IntegrityAlg)
	require.Equal(t, models.AccessType__3_GPP_ACCESS, ue.AnType)
	require.Equal(t, uint8(5), ue.SQNIndBitLen)

	// Test basic capability and bearer methods
	cap5gmm := ue.Get5GMMCapability()
	require.NotNil(t, cap5gmm)

	secCap := ue.GetUESecurityCapability()
	require.NotNil(t, secCap)

	bearer := ue.GetBearerType()
	require.Equal(t, security.Bearer3GPP, bearer)
}

func TestSecurityProcedures(t *testing.T) {
	// Setup temporary config for SQN syncing
	tmpDir := t.TempDir()
	originalConfig := "../../config/n3ue.yaml"
	tmpConfig := filepath.Join(tmpDir, "n3ue.yaml")

	srcFile, err := os.Open(originalConfig)
	require.NoError(t, err)
	destFile, err := os.Create(tmpConfig)
	require.NoError(t, err)
	_, err = io.Copy(destFile, srcFile)
	require.NoError(t, err)
	err = destFile.Close()
	require.NoError(t, err)
	err = srcFile.Close()
	require.NoError(t, err)

	err = factory.InitConfigFactory(tmpConfig)
	require.NoError(t, err)
	k, err := hex.DecodeString("465B5CE8B199B49FAA5F0A2EE238A6BC")
	require.NoError(t, err)
	opc, err := hex.DecodeString("E8ED289DEBA952E4283B54E88E6183CA")
	require.NoError(t, err)
	amf, err := hex.DecodeString("8000")
	require.NoError(t, err)
	rand, err := hex.DecodeString("23553CBE9637A89D218AE64DAE47BF35")
	require.NoError(t, err)
	sqn, err := hex.DecodeString("000000000020")
	require.NoError(t, err)
	snName := "5G:mnc093.mcc208.3gppnetwork.org"

	ue := NewRanUeContext("imsi-208930000000001", 1, security.AlgCiphering128NEA0,
		security.AlgIntegrity128NIA1, models.AccessType__3_GPP_ACCESS, "000000000000")
	ue.AuthenticationSubs = GetAuthSubscription(
		hex.EncodeToString(k),
		hex.EncodeToString(sqn),
		hex.EncodeToString(amf),
		hex.EncodeToString(opc),
		"",
	)

	// Generate valid AKA parameters for matching
	// nolint:dogsled
	_, _, _, autn, err := milenage.GenerateAKAParameters(opc, k, rand, sqn, amf)
	require.NoError(t, err)

	// Test 1: VerifyAUTN
	result, err := ue.VerifyAUTN(autn, rand)
	require.NoError(t, err, "AUTN Verification should succeed")
	require.Equal(t, AuthSuccess, result)

	// Test 2: DeriveRESstarAndSetKey
	resStar := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand, snName, autn)
	require.NotNil(t, resStar)
	require.Len(t, resStar, 16) // RES* is 128 bits

	// Test 3: GenerateAUTS (simulate an Out of Sync scenario)
	sqnOutOfSync, err := hex.DecodeString("000000000040")
	require.NoError(t, err)
	// nolint:dogsled
	_, _, _, autnOos, err := milenage.GenerateAKAParameters(opc, k, rand, sqnOutOfSync, amf)
	require.NoError(t, err)
	auts, err := ue.GenerateAUTS(rand)
	require.NoError(t, err, "GenerateAUTS should succeed")
	require.Len(t, auts, 14)
	_ = autnOos
}
