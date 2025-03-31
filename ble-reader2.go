package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/go-ble/ble"
	"github.com/go-ble/ble/examples/lib/dev"
)

const (
	serviceUUID            = "5f6d4f535f5250435f5356435f49445f"
	characteristicUUIDData = "5f6d4f535f5250435f646174615f5f5f"
	characteristicUUIDRx   = "5f6d4f535f5250435f72785f63746c5f"
	characteristicUUIDTx   = "5f6d4f535f5250435f74785f63746c5f"
)

type DeviceInfo struct {
	Address string
	Name    string
}

func normalizeUUID(uuid string) string {
	uuid = strings.ToLower(uuid)
	if len(uuid) == 32 {
		return fmt.Sprintf("%s-%s-%s-%s-%s", 
			uuid[0:8], uuid[8:12], uuid[12:16], uuid[16:20], uuid[20:32])
	}
	return uuid
}

func findYetiDevice(ctx context.Context) (*DeviceInfo, error) {
	d, err := dev.NewDevice("default")
	if err != nil {
		return nil, fmt.Errorf("failed to initialize device: %v", err)
	}
	ble.SetDefaultDevice(d)

	fmt.Println("Scanning for Yeti devices...")
	var yetiDevice *DeviceInfo

	err = ble.Scan(ctx, true, func(adv ble.Advertisement) {
		if strings.HasPrefix(adv.LocalName(), "Yeti") {
			fmt.Printf("Found device: %s (%s)\n", adv.LocalName(), adv.Addr().String())
			yetiDevice = &DeviceInfo{
				Address: adv.Addr().String(),
				Name:    adv.LocalName(),
			}
		}
	}, nil)

	if err != nil && err != context.DeadlineExceeded {
		return nil, fmt.Errorf("scan failed: %v", err)
	}

	if yetiDevice == nil {
		return nil, fmt.Errorf("no Yeti device found")
	}

	return yetiDevice, nil
}

func connectAndHandleYeti(ctx context.Context, deviceAddr string) error {
	client, err := ble.Dial(ctx, ble.NewAddr(deviceAddr))
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer client.CancelConnection()

	fmt.Printf("Connected to %s\n", deviceAddr)

	// Exchange MTU for larger packet size
	if _, err := client.ExchangeMTU(256); err != nil {
		fmt.Printf("Warning: MTU exchange failed: %v\n", err)
	}

	// Discover services
	ss, err := client.DiscoverServices(nil)
	if err != nil {
		return fmt.Errorf("failed to discover services: %v", err)
	}

	// Find the RPC service
	var rpcService *ble.Service
	for _, s := range ss {
		if strings.Contains(strings.ToLower(s.UUID.String()), serviceUUID) {
			rpcService = s
			break
		}
	}

	if rpcService == nil {
		return fmt.Errorf("RPC service not found")
	}

	// Discover characteristics
	cs, err := client.DiscoverCharacteristics(nil, rpcService)
	if err != nil {
		return fmt.Errorf("failed to discover characteristics: %v", err)
	}

	// Find required characteristics
	var dataChar, rxChar, txChar *ble.Characteristic
	for _, c := range cs {
		cUUID := strings.ToLower(c.UUID.String())
		switch {
		case strings.Contains(cUUID, characteristicUUIDData):
			dataChar = c
		case strings.Contains(cUUID, characteristicUUIDRx):
			rxChar = c
		case strings.Contains(cUUID, characteristicUUIDTx):
			txChar = c
		}
	}

	if dataChar == nil || rxChar == nil || txChar == nil {
		return fmt.Errorf("missing required characteristics")
	}

	// Send commands to initiate data transfer
	if err := client.WriteCharacteristic(txChar, []byte{0x00, 0x00, 0x00, 0x1f}, false); err != nil {
		return fmt.Errorf("failed to write to TX characteristic: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	if err := client.WriteCharacteristic(dataChar, []byte(`{"id":2,"method":"join-direct"}`), false); err != nil {
		return fmt.Errorf("failed to write to DATA characteristic: %v", err)
	}
	time.Sleep(1 * time.Second)

	// Read response data
	fmt.Println("\nReading device data...")
	var fullData []byte
	maxReadAttempts := 10

	for i := 0; i < maxReadAttempts; i++ {
		dataPart, err := client.ReadCharacteristic(dataChar)
		if err != nil {
			return fmt.Errorf("read failed (attempt %d): %v", i+1, err)
		}
		
		fullData = append(fullData, dataPart...)
		
		// Check if we have complete JSON
		var response map[string]interface{}
		if json.Unmarshal(fullData, &response) == nil {
			break
		}
		
		time.Sleep(500 * time.Millisecond)
	}

	if len(fullData) == 0 {
		return fmt.Errorf("no data received from device")
	}

	// Print complete raw JSON response
	fmt.Printf("\nComplete response:\n%s\n", string(fullData))

	// Parse and display the state information
	var responseData struct {
		Result struct {
			Body struct {
				State map[string]interface{} `json:"state"`
			} `json:"body"`
		} `json:"result"`
	}

	if err := json.Unmarshal(fullData, &responseData); err != nil {
		return fmt.Errorf("failed to parse response: %v", err)
	}

	stateBytes, err := json.MarshalIndent(responseData.Result.Body.State, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to format state: %v", err)
	}

	fmt.Printf("\nDevice state:\n%s\n", string(stateBytes))
	return nil
}

func main() {
	scanCtx, scanCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer scanCancel()

	yetiDevice, err := findYetiDevice(scanCtx)
	if err != nil {
		log.Fatalf("Error finding Yeti device: %v", err)
	}

	fmt.Printf("Using device: %s (%s)\n", yetiDevice.Name, yetiDevice.Address)

	for {
		connCtx, connCancel := context.WithTimeout(context.Background(), 60*time.Second)
		
		if err := connectAndHandleYeti(connCtx, yetiDevice.Address); err != nil {
			log.Printf("Error: %v\n", err)
		}
		
		connCancel()
		
		fmt.Println("\nWaiting 30 seconds before next attempt...")
		time.Sleep(30 * time.Second)
	}
}