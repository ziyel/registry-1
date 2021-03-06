package model

import (
	"strings"
	"testing"

	"github.com/lodastack/models"
)

var testNewAlarmMap map[string]string = map[string]string{
	"name":        "cpu.idle < 10",
	"default":     "true",
	"trigger":     "threshold",
	"enable":      "true",
	"every":       "1m",
	"period":      "1m",
	"measurement": "cpu.idle",
	"func":        "mean",
	"expression":  "<",
	"value":       "10",
	"groupby":     "host",
	"groups":      "op",
	"level":       "2",
	"message":     "cpu.idle < 10",
	"md5":         "md5",
	"rp":          "loda",
	"shift":       "5",
	"alert":       "sms",
	"where":       "",

	"blockstep":    "10",
	"maxblocktime": "60",
	"starttime":    "0",
	"endtime":      "0",
}

func TestNewAlarmByRes(t *testing.T) {
	// case1
	delete(testNewAlarmMap, "name")
	if _, err := NewAlarmByRes("test", testNewAlarmMap, ""); err == nil {
		t.Fatal("case1 success, not match with expect")
	}

	testNewAlarmMap["name"] = "cpu.idle < 10"

	// case2
	if alarm, err := NewAlarmByRes("", testNewAlarmMap, ""); err == nil {
		t.Fatalf("case2 success, not match with expect, %+v", *alarm)
	}

	// case3
	if alarm, err := NewAlarmByRes("test", testNewAlarmMap, ""); err != nil ||
		alarm.MD5 == "md5" ||
		alarm.DB != "collect.test" ||
		len(strings.Split(alarm.Version, models.VersionSep)) != 4 {
		t.Fatalf("case3 success, not match with expect, %+v", *alarm)
	}

	// case4
	testNewAlarmMap["trigger"], testNewAlarmMap["value"] = models.ThresHold, ""
	if alarm, err := NewAlarmByRes("", testNewAlarmMap, ""); err == nil {
		t.Fatalf("case2 success, not match with expect, %+v", *alarm)
	}
	testNewAlarmMap["trigger"], testNewAlarmMap["shift"] = models.Relative, ""
	if alarm, err := NewAlarmByRes("", testNewAlarmMap, ""); err == nil {
		t.Fatalf("case2 success, not match with expect, %+v", *alarm)
	}

	// case5
	testNewAlarmMap["trigger"], testNewAlarmMap["value"] = models.ThresHold, "1"
	if alarm, err := NewAlarmByRes("test", testNewAlarmMap, ""); err != nil {
		t.Fatalf("case2 success, not match with expect, %+v", *alarm)
	}
	testNewAlarmMap["trigger"], testNewAlarmMap["shift"] = models.Relative, "1"
	if alarm, err := NewAlarmByRes("test", testNewAlarmMap, ""); err != nil {
		t.Fatalf("case2 success, not match with expect, %+v", *alarm)
	}

	// case 6
	if alarm, err := NewAlarmByRes("test", testNewAlarmMap, "ID-test"); err != nil ||
		alarm.ID != "ID-test" ||
		alarm.MD5 == "md5" ||
		alarm.DB != "collect.test" ||
		len(strings.Split(alarm.Version, models.VersionSep)) != 4 {
		t.Fatalf("case4 success, not match with expect, %+v", *alarm)
	} else {
		versionSplit := strings.Split(alarm.Version, models.VersionSep)
		if versionSplit[0] != "test" ||
			versionSplit[1] != "cpu.idle" ||
			versionSplit[2] != "ID-test" {
			t.Fatalf("case4 success, not match with expect, %+v", *alarm)
		}
	}

}
