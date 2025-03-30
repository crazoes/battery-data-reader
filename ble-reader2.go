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
	// UUIDs from the scan output, with proper casing
	serviceUUID            = "5f6d4f535f5250435f5356435f49445f"
	characteristicUUIDData = "5f6d4f535f5250435f646174615f5f5f"
	characteristicUUIDRx   = "5f6d4f535f5250435f72785f63746c5f"
	characteristicUUIDTx   = "5f6d4f535f5250435f74785f63746c5f"
)

type DeviceInfo struct {
	Address string
	Name    string
}

// Convert UUIDs to standard format if needed
func normalizeUUID(uuid string) string {
	// Convert to lowercase for consistent comparison
	uuid = strings.ToLower(uuid)
	
	// Add dashes if needed
	if len(uuid) == 32 {
		return fmt.Sprintf("%s-%s-%s-%s-%s", 
			uuid[0:8], uuid[8:12], uuid[12:16], uuid[16:20], uuid[20:32])
	}
	return uuid
}

func findYetiDevice(ctx context.Context) (*DeviceInfo, error) {
	// Initialize BLE device
	d, err := dev.NewDevice("default")
	if err != nil {
		return nil, fmt.Errorf("failed to initialize device: %v", err)
	}
	ble.SetDefaultDevice(d)

	// Scan for devices
	fmt.Println("Scanning for devices...")
	var yetiDevice *DeviceInfo

	err = ble.Scan(ctx, true, func(adv ble.Advertisement) {
		if strings.HasPrefix(adv.LocalName(), "Yeti") {
			fmt.Printf("Found device %s: %s\n", adv.LocalName(), adv.Addr().String())
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
	// Connect to the device
	client, err := ble.Dial(ctx, ble.NewAddr(deviceAddr))
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer client.CancelConnection()

	fmt.Printf("Connected to %s\n", deviceAddr)

	// Attempt to negotiate a larger MTU
	mtu, err := client.ExchangeMTU(256)
	if err != nil {
		fmt.Printf("MTU exchange failed, using default: %v\n", err)
	} else {
		fmt.Printf("Using MTU size: %d\n", mtu)
	}

	// Discover services
	fmt.Println("Discovering services...")
	ss, err := client.DiscoverServices(nil)
	if err != nil {
		return fmt.Errorf("failed to discover services: %v", err)
	}
	fmt.Printf("Found %d services\n", len(ss))

	// Find the correct service by UUID
	var rpcService *ble.Service
	for _, s := range ss {
		uuidStr := strings.ToLower(s.UUID.String())
		fmt.Printf("Service: %s\n", uuidStr)
		if strings.Contains(uuidStr, serviceUUID) {
			rpcService = s
			fmt.Println("  ** Found RPC service")
			break
		}
	}

	if rpcService == nil {
		return fmt.Errorf("RPC service not found")
	}

	// Discover characteristics for the RPC service
	cs, err := client.DiscoverCharacteristics(nil, rpcService)
	if err != nil {
		return fmt.Errorf("failed to discover characteristics: %v", err)
	}
	fmt.Printf("  Found %d characteristics\n", len(cs))

	// Find the required characteristics
	var dataChar, rxChar, txChar *ble.Characteristic
	foundChars := make(map[string]bool)

	for _, c := range cs {
		cUUID := strings.ToLower(c.UUID.String())
		fmt.Printf("  Characteristic: %s\n", cUUID)
		
		if strings.Contains(cUUID, characteristicUUIDData) {
			dataChar = c
			foundChars["data"] = true
			fmt.Println("  ** Found DATA characteristic")
			
			// Log properties to debug
			props := c.Property
			fmt.Printf("  DATA Properties: Read=%v, Write=%v, WriteWithoutResp=%v, Notify=%v\n", 
				props&ble.CharRead != 0, 
				props&ble.CharWrite != 0, 
				props&ble.CharWriteNR != 0,
				props&ble.CharNotify != 0)
		} else if strings.Contains(cUUID, characteristicUUIDRx) {
			rxChar = c
			foundChars["rx"] = true
			fmt.Println("  ** Found RX characteristic")
		} else if strings.Contains(cUUID, characteristicUUIDTx) {
			txChar = c
			foundChars["tx"] = true
			fmt.Println("  ** Found TX characteristic")
		}
	}

	// Check if all necessary characteristics were found
	if !foundChars["data"] || !foundChars["rx"] || !foundChars["tx"] {
		if !foundChars["data"] {
			fmt.Printf("DATA characteristic (%s) not found\n", characteristicUUIDData)
		}
		if !foundChars["rx"] {
			fmt.Printf("RX characteristic (%s) not found\n", characteristicUUIDRx)
		}
		if !foundChars["tx"] {
			fmt.Printf("TX characteristic (%s) not found\n", characteristicUUIDTx)
		}
		return fmt.Errorf("failed to find all required characteristics")
	}

	fmt.Println("All required characteristics found. Proceeding with communication...")

	// Subscribe to notifications if needed
	if rxChar.Property&ble.CharNotify != 0 {
		fmt.Println("Setting up notifications for RX...")
		if err := client.Subscribe(rxChar, false, func(data []byte) {
			fmt.Printf("Notification from RX: %x\n", data)
		}); err != nil {
			fmt.Printf("Failed to subscribe to RX notifications: %v\n", err)
		}
	}

	// Write to characteristics (matching Python code structure)
	command := []byte{0x00, 0x00, 0x00, 0x1f}
	fmt.Println("Writing to TX characteristic...")
	// Try WriteWithoutResponse first (false parameter)
	if err := client.WriteCharacteristic(txChar, command, false); err != nil {
		fmt.Printf("WriteWithoutResponse to TX failed, trying with response: %v\n", err)
		if err := client.WriteCharacteristic(txChar, command, true); err != nil {
			return fmt.Errorf("failed to write to TX characteristic: %v", err)
		}
	}

	// Short delay between operations
	time.Sleep(300 * time.Millisecond)

	command2 := []byte(`{"id":2,"method":"join-direct"}`)
	fmt.Println("Writing to DATA characteristic...")
	// Try WriteWithoutResponse first (false parameter)
	if err := client.WriteCharacteristic(dataChar, command2, false); err != nil {
		fmt.Printf("WriteWithoutResponse to DATA failed, trying with response: %v\n", err)
		if err := client.WriteCharacteristic(dataChar, command2, true); err != nil {
			return fmt.Errorf("failed to write to DATA characteristic: %v", err)
		}
	}

	// Give device time to process
	time.Sleep(1 * time.Second)

	// Read from characteristics
	fmt.Println("Reading from RX characteristic...")
	rxData, err := client.ReadCharacteristic(rxChar)
	if err != nil {
		fmt.Printf("Failed to read from RX, continuing anyway: %v\n", err)
	} else {
		fmt.Printf("RX data: %x\n", rxData)
	}

	fmt.Println("Reading from DATA characteristic (part 1)...")
	dataPart1, err := client.ReadCharacteristic(dataChar)
	if err != nil {
		return fmt.Errorf("failed to read from DATA characteristic (part 1): %v", err)
	}
	fmt.Printf("Data part 1: %s\n", string(dataPart1))

	time.Sleep(300 * time.Millisecond)

	fmt.Println("Reading from DATA characteristic (part 2)...")
	dataPart2, err := client.ReadCharacteristic(dataChar)
	if err != nil {
		return fmt.Errorf("failed to read from DATA characteristic (part 2): %v", err)
	}
	fmt.Printf("Data part 2: %s\n", string(dataPart2))

	// Combine and parse the response
	combinedData := append(dataPart1, dataPart2...)
	fmt.Printf("Received combined data: %s\n", string(combinedData))
	
	// Only try to parse if we have data
	if len(combinedData) > 0 {
		var responseData map[string]interface{}
		if err := json.Unmarshal(combinedData, &responseData); err != nil {
			fmt.Printf("Warning: failed to parse response: %v\n", err)
		} else {
			// Extract and print the state (similar to Python code)
			result, ok := responseData["result"].(map[string]interface{})
			if !ok {
				fmt.Println("Warning: response missing 'result' field")
			} else {
				body, ok := result["body"].(map[string]interface{})
				if !ok {
					fmt.Println("Warning: response missing 'body' field")
				} else {
					state, ok := body["state"]
					if !ok {
						fmt.Println("Warning: response missing 'state' field")
					} else {
						fmt.Printf("Device state: %v\n", state)
					}
				}
			}
		}
	}

	return nil
}

func main() {
	// Create a context with timeout for scanning
	scanCtx, scanCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer scanCancel()

	// Find Yeti device
	yetiDevice, err := findYetiDevice(scanCtx)
	if err != nil {
		log.Fatalf("Error finding Yeti device: %v", err)
	}

	fmt.Printf("Found Yeti device: %s (%s)\n", yetiDevice.Name, yetiDevice.Address)

	// Loop with a fresh context for each connection attempt
	for {
		// Create a new context for each connection attempt
		connCtx, connCancel := context.WithTimeout(context.Background(), 60*time.Second)
		
		// Connect and handle communication
		if err := connectAndHandleYeti(connCtx, yetiDevice.Address); err != nil {
			log.Printf("Error: %v\n", err)
		}
		
		// Cancel the context after the attempt is complete
		connCancel()
		
		// Wait before trying again
		time.Sleep(30 * time.Second)
	}
}
