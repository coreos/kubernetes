package tpm

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-tspi/tpmclient"
	"github.com/coreos/go-tspi/tspiconst"
	"github.com/coreos/go-tspi/verification"
	"github.com/golang/glog"
	"github.com/mitchellh/mapstructure"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/unversioned"
	"k8s.io/kubernetes/pkg/client/restclient"
	"k8s.io/kubernetes/pkg/client/typed/dynamic"
)

type TPMHandler struct {
	tpmclient    *dynamic.ResourceClient
	PolicyClient *dynamic.ResourceClient
}

var TPMResource string = "coreos.com"

type Tpm struct {
	// The TPM's EK certificate
	EKCert []byte
	// The encrypted AIK keyblob
	AIKBlob []byte
	// The public half of AIK
	AIKPub []byte
	// The current address associated with the TPM
	Address string
}

func (t *TPMHandler) Setup(refconfig *restclient.Config) error {
	config := *refconfig
	tpmclient, err := dynamic.NewClient(&config)
	if err != nil {
		return err
	}
	tpmresource := &unversioned.APIResource{
		Kind:       "Tpm",
		Name:       "tpms",
		Namespaced: true,
	}
	tpmResourceClient := tpmclient.Resource(tpmresource, "default")
	t.tpmclient = tpmResourceClient

	config.APIPath = "apis/tpm.coreos.com"
	policyclient, err := dynamic.NewClient(&config)
	if err != nil {
		return err
	}
	policyresource := &unversioned.APIResource{
		Kind:       "Policy",
		Name:       "policies",
		Namespaced: true,
	}
	policyresourceclient := policyclient.Resource(policyresource, "default")
	t.PolicyClient = policyresourceclient

	return nil
}

func (t *TPMHandler) GetPolicies() ([]map[string]PCRConfig, error) {
	var configs []map[string]PCRConfig
	var options api.ListOptions

	unstructuredPolicies, err := t.PolicyClient.List(&options)
	if err != nil {
		return nil, err
	}
	for _, unstructuredPolicy := range unstructuredPolicies.Items {
		config := make(map[string]PCRConfig)
		policy := unstructuredPolicy.Object["policy"]
		if policy == nil {
			continue
		}
		policymap, ok := policy.(map[string]interface{})
		if !ok {
			glog.Errorf("Unable to decode unstructured object %s", unstructuredPolicy.GetName())
			continue
		}
		for pcr, unstructuredpcrconfig := range policymap {
			var pcrconfig PCRConfig
			err = mapstructure.Decode(unstructuredpcrconfig, &pcrconfig)
			if err != nil {
				glog.Errorf("Unable to unmarshal policy json from %s", unstructuredPolicy.GetName())
			}
			pcrconfig.Source = unstructuredPolicy.GetName()
			pcrconfig.Policyref = unstructuredPolicy.GetSelfLink()
			config[pcr] = pcrconfig
		}
		configs = append(configs, config)
	}
	return configs, nil
}

func (t *TPMHandler) Get(address string, allowEmpty bool) (*Tpm, error) {
	c := tpmclient.New(address, 30*time.Second)
	ekcert, err := c.GetEKCert()

	if err != nil {
		return nil, err
	}

	eksha := sha1.Sum(ekcert)
	ekhash := hex.EncodeToString(eksha[:])
	tpm := &Tpm{}
	unstructuredTpm, err := t.tpmclient.Get(ekhash)

	if err != nil {
		if allowEmpty == false {
			return nil, fmt.Errorf("TPM does not exist and automatic creation is forbidden")
		}
		err = verification.VerifyEKCert(ekcert)
		if err != nil {
			return nil, err
		}
		tpm = &Tpm{
			EKCert: ekcert,
		}
		unstructuredTpm.SetKind("Tpm")
		unstructuredTpm.SetAPIVersion("coreos.com/v1")
		unstructuredTpm.SetName(ekhash)
		unstructuredTpm.Object = make(map[string]interface{})
		unstructuredTpm.Object["EKCert"] = base64.StdEncoding.EncodeToString(tpm.EKCert)
		unstructuredTpm.Object["AIKPub"] = ""
		unstructuredTpm.Object["AIKBlob"] = ""

		unstructuredTpm, err = t.tpmclient.Create(unstructuredTpm)
		if err != nil {
			return nil, err
		}
		unstructuredTpm, err = t.tpmclient.Get(ekhash)
		if err != nil {
			return nil, err
		}
	}

	tpm.EKCert, err = base64.StdEncoding.DecodeString(unstructuredTpm.Object["EKCert"].(string))
	if err != nil {
		glog.Errorf("Unable to decode TPM EK Cert from %s", unstructuredTpm.GetName())
		return nil, err
	}
	tpm.AIKPub, _ = base64.StdEncoding.DecodeString(unstructuredTpm.Object["AIKPub"].(string))
	if err != nil {
		glog.Errorf("Unable to decode TPM public AIK from %s", unstructuredTpm.GetName())
		return nil, err
	}
	tpm.AIKBlob, _ = base64.StdEncoding.DecodeString(unstructuredTpm.Object["AIKBlob"].(string))
	if err != nil {
		glog.Errorf("Unable to decode TPM AIK blob from %s", unstructuredTpm.GetName())
		return nil, err
	}

	if len(tpm.EKCert) == 0 {
		tpm.EKCert = ekcert
	}
	if len(tpm.AIKPub) == 0 || len(tpm.AIKBlob) == 0 {
		secret := make([]byte, 16)
		_, err = rand.Read(secret)
		if err != nil {
			return nil, err
		}
		aikpub, aikblob, err := c.GenerateAIK()
		if err != nil {
			return nil, err
		}
		asymenc, symenc, err := verification.GenerateChallenge(ekcert, aikpub, secret)
		if err != nil {
			return nil, err
		}
		response, err := c.ValidateAIK(aikblob, asymenc, symenc)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(response[:], secret) {
			return nil, fmt.Errorf("AIK could not be validated")
		}
		tpm.AIKPub = aikpub
		tpm.AIKBlob = aikblob
		unstructuredTpm.SetName(ekhash)
		unstructuredTpm.Object["EKCert"] = tpm.EKCert
		unstructuredTpm.Object["AIKPub"] = tpm.AIKPub
		unstructuredTpm.Object["AIKBlob"] = tpm.AIKBlob
		unstructuredTpm, err = t.tpmclient.Update(unstructuredTpm)
		if err != nil {
			return nil, err
		}
	}

	tpm.Address = address
	return tpm, nil
}

func Quote(tpm *Tpm) ([][]byte, []tspiconst.Log, error) {
	c := tpmclient.New(tpm.Address, 30*time.Second)
	quote, log, err := c.GetQuote(tpm.AIKPub, tpm.AIKBlob, []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	return quote, log, err
}

func ValidateLogConsistency(log []tspiconst.Log) error {
	for _, entry := range log {
		hash := sha1.Sum(entry.Event[:])
		if bytes.Equal(hash[:], entry.PcrValue[:]) {
			continue
		}
		return fmt.Errorf("Log entry is inconsistent with claimed PCR value: %x vs %x", entry.PcrValue[:], hash[:])
	}

	return nil
}

func ValidateLog(log []tspiconst.Log, quote [][]byte) error {
	// Replay the log and generate the hash values we'd have if the log is correct
	// Each PCR is 20 bytes, and we support up to 24 of them
	var virt_pcrs [24][20]byte

	for _, entry := range log {
		// Append the SHA in the log to the current PCR value and generate the
		// new PCR value
		var tmp [40]byte
		cur := tmp[0:20]
		new := tmp[20:40]
		copy(cur, virt_pcrs[entry.Pcr][:])
		copy(new, entry.PcrValue[:])
		virt_pcrs[entry.Pcr] = sha1.Sum(tmp[:])
	}

	// And now check that the actual PCR values match the calculated ones
	for pcr, _ := range quote {
		if len(quote[pcr]) == 0 {
			continue
		}
		if !bytes.Equal(virt_pcrs[pcr][:], quote[pcr]) {
			glog.Errorf("Log fails to match for PCR %d", pcr)
			glog.Errorf("%x vs %x", virt_pcrs[pcr], quote[pcr])
			return fmt.Errorf("Log doesn't validate")
		}
	}

	return nil
}

type PCRValue struct {
	Value       string
	Description string
}

type PCRConfig struct {
	Policyref    string
	Source       string
	RawValues    []PCRValue
	ASCIIValues  []PCRDescription
	BinaryValues []PCRDescription
}

type PCRDescription struct {
	Prefix string
	Values []PCRValue
}

type ValidatedLog struct {
	tspiconst.Log
	Valid       bool
	Description string
	Source      string
	Match       string
	Policyref   string
}

func ValidateRawPCR(pcrval []byte, valid []PCRValue) bool {
	for _, validpcr := range valid {
		if validpcr.Value == "*" {
			return true
		}
		validHex, err := hex.DecodeString(validpcr.Value)
		if err != nil {
			glog.Errorf("Couldn't parse %s as hex", validpcr)
			continue
		}
		if bytes.Equal(validHex, pcrval) {
			return true
		}
	}
	return false
}

func ValidateBinaryPCR(pcr int, log []ValidatedLog, values []PCRDescription, source string, policyref string) {
	for index, logentry := range log {
		var prefix string

		if logentry.Valid == true {
			continue
		}

		if logentry.Pcr != int32(pcr) {
			continue
		}

		prefix = strings.Split(string(logentry.Event), " ")[0]
		for _, config := range values {
			if config.Prefix != "" && prefix != config.Prefix {
				continue
			}
			for _, validpcr := range config.Values {
				if validpcr.Value == "*" {
					log[index].Valid = true
					log[index].Description = validpcr.Description
					log[index].Source = source
					log[index].Policyref = policyref
					log[index].Match = validpcr.Value
					continue
				}
				validHex, err := hex.DecodeString(validpcr.Value)
				if err != nil {
					glog.Errorf("Couldn't parse %s as hex", validpcr.Value)
					continue
				}
				if bytes.Equal(validHex, logentry.PcrValue[:]) {
					log[index].Valid = true
					log[index].Description = validpcr.Description
					log[index].Source = source
					log[index].Policyref = policyref
					log[index].Match = validpcr.Value
				}
			}
		}
	}
	return
}

func ValidateASCIIPCR(pcr int, log []ValidatedLog, values []PCRDescription, source string, policyref string) {
	for index, logentry := range log {
		var prefix string
		var event string

		if logentry.Valid == true {
			continue
		}

		// Only verify events of type 13
		if logentry.Eventtype != 13 {
			continue
		}
		if logentry.Pcr != int32(pcr) {
			continue
		}

		// Ensure that the event matches the hash
		hash := sha1.Sum(logentry.Event[:])
		if !(bytes.Equal(hash[:], logentry.PcrValue[:])) {
			continue
		}

		substrs := strings.SplitAfterN(string(logentry.Event), " ", 2)
		if len(substrs) == 2 {
			prefix = strings.TrimRight(substrs[0], " ")
			event = substrs[1]
		} else {
			event = substrs[0]
		}
		for _, config := range values {
			if config.Prefix != "" && prefix != config.Prefix {
				continue
			}
			for _, validpcr := range config.Values {
				match, err := regexp.MatchString(validpcr.Value, event)
				if err == nil && match == true {
					log[index].Valid = true
					log[index].Description = validpcr.Description
					log[index].Source = source
					log[index].Policyref = policyref
					log[index].Match = validpcr.Value
					break
				}
			}
		}
	}
	return
}

func ValidatePCRs(log []tspiconst.Log, quote [][]byte, pcrconfig []map[string]PCRConfig) ([]ValidatedLog, error) {
	validatedlog := make([]ValidatedLog, len(log))
	for index, logentry := range log {
		validatedlog[index] = ValidatedLog{logentry, false, "", "", "", ""}
	}
	for _, config := range pcrconfig {
		for pcrname, _ := range config {
			pcr, _ := strconv.Atoi(pcrname)
			if len(config[pcrname].RawValues) != 0 {
				valid := ValidateRawPCR(quote[pcr], config[pcrname].RawValues)
				// If the raw PCR is valid then all log entries for that PCR are valid
				if valid == true {
					for index, _ := range validatedlog {
						if int(validatedlog[index].Pcr) == pcr {
							validatedlog[index].Valid = true
							validatedlog[index].Source = config[pcrname].Source
							validatedlog[index].Policyref = config[pcrname].Policyref
						}
					}
					continue
				}
			}

			if len(config[pcrname].BinaryValues) != 0 {
				ValidateBinaryPCR(pcr, validatedlog, config[pcrname].BinaryValues, config[pcrname].Source, config[pcrname].Policyref)
			}

			if len(config[pcrname].ASCIIValues) != 0 {
				ValidateASCIIPCR(pcr, validatedlog, config[pcrname].ASCIIValues, config[pcrname].Source, config[pcrname].Policyref)
			}
		}
	}

	// The validation fails if there's any events that weren't validated
	for _, logevent := range validatedlog {
		if logevent.Valid == false {
			glog.Errorf("PCR state is invalid")
			return validatedlog, fmt.Errorf("PCR state is invalid")
		}
	}

	return validatedlog, nil
}
