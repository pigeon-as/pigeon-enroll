package action

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/shoenig/test/must"
)

func TestLuksRecovery_SecretNames(t *testing.T) {
	cfgJSON, _ := json.Marshal(map[string]interface{}{
		"device":   "/dev/md1",
		"secret":   "luks_recovery",
		"key_slot": 1,
	})

	a, err := New(Config{Type: "luks-recovery", Body: jsonToBody(t, cfgJSON)})
	must.NoError(t, err)
	must.Eq(t, []string{"luks_recovery"}, a.SecretNames())
}

func TestLuksRecovery_MissingKeySlot(t *testing.T) {
	cfgJSON, _ := json.Marshal(map[string]interface{}{
		"device": "/dev/md1",
		"secret": "luks_recovery",
	})

	_, err := newLuksRecovery(jsonToBody(t, cfgJSON))
	must.Error(t, err)
}

func TestLuksRecovery_CustomKeySlot(t *testing.T) {
	cfgJSON, _ := json.Marshal(map[string]interface{}{
		"device":      "/dev/md1",
		"mapped_name": "data",
		"key_slot":    3,
		"secret":      "luks_recovery",
	})

	a, err := newLuksRecovery(jsonToBody(t, cfgJSON))
	must.NoError(t, err)
	must.EqOp(t, 3, a.cfg.KeySlot)
	must.EqOp(t, "data", a.cfg.MappedName)
}

func TestLuksRecovery_MissingDevice(t *testing.T) {
	cfgJSON, _ := json.Marshal(map[string]interface{}{
		"secret":   "luks_recovery",
		"key_slot": 1,
	})

	_, err := newLuksRecovery(jsonToBody(t, cfgJSON))
	must.Error(t, err)
}

func TestLuksRecovery_MissingSecret(t *testing.T) {
	cfgJSON, _ := json.Marshal(map[string]interface{}{
		"device":   "/dev/md1",
		"key_slot": 1,
	})

	_, err := newLuksRecovery(jsonToBody(t, cfgJSON))
	must.Error(t, err)
}

func TestLuksRecovery_MissingSecretInDerived(t *testing.T) {
	cfgJSON, _ := json.Marshal(map[string]interface{}{
		"device":   "/dev/md1",
		"secret":   "luks_recovery",
		"key_slot": 1,
	})

	a, err := newLuksRecovery(jsonToBody(t, cfgJSON))
	must.NoError(t, err)

	err = a.Run(context.Background(), slog.Default(), map[string]string{})
	must.Error(t, err)
}
