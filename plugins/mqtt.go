package plugins

import (
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

func CheckMqttServer(address string, timeout float64) string {
	opts := mqtt.NewClientOptions().AddBroker("tcp://" + address)
	opts.SetClientID("mqtt_detection_tool")
	opts.SetConnectTimeout(time.Duration(timeout) * time.Second)
	client := mqtt.NewClient(opts)
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		return ""
	}
	defer client.Disconnect(250)
	return "Mqtt"
}
