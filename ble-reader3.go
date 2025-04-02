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
	// Goal Zero Yeti constants
	serviceUUID            = "5f6d4f535f5250435f5356435f49445f"
	characteristicUUIDData = "5f6d4f535f5250435f646174615f5f5f"
	characteristicUUIDRx   = "5f6d4f535f5250435f72785f63746c5f"
	characteristicUUIDTx   = "5f6d4f535f5250435f74785f63746c5f"

	// Jackery constants
	jackeryWriteCharUUID = "0000ee01-0000-1000-8000-00805f9b34fb"
	jackeryNotifyCharUUID = "0000ee02-0000-1000-8000-00805f9b34fb"
	defaultJackeryKey = "6*SY1c5B9@"
)

type DeviceInfo struct {
	Address string
	Name    string
	Type    string // "Yeti", "gz", or "Jackery"
}

// RC4 implementation for Jackery decryption
type RC4Cipher struct {
	S    []byte
	i, j uint8
}

func NewRC4Cipher(key []byte) *RC4Cipher {
    s := make([]byte, 256)
    for i := 0; i < 256; i++ {
        s[i] = byte(i)
    }

    var j uint8 = 0
    for i := 0; i < 256; i++ {
        j = j + s[i] + key[i%len(key)]
        s[i], s[j] = s[j], s[i]
    }

    return &RC4Cipher{S: s, i: 0, j: 0}
}

func (c *RC4Cipher) GetByte() byte {
    c.i = c.i + 1
    c.j = c.j + c.S[c.i]
    c.S[c.i], c.S[c.j] = c.S[c.j], c.S[c.i]
    return c.S[(uint8(c.S[c.i])+uint8(c.S[c.j]))]
}

func (c *RC4Cipher) Encrypt(data []byte) []byte {
	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = b ^ c.GetByte()
	}
	return result
}

func DecryptJackery(key string, data []byte) []byte {
	keyBytes := []byte(key)
	rc4 := NewRC4Cipher(keyBytes)
	return rc4.Encrypt(data)
}

func scanForDevices(ctx context.Context) ([]*DeviceInfo, error) {
    d, err := dev.NewDevice("default")
    if err != nil {
        return nil, fmt.Errorf("failed to initialize device: %v", err)
    }
    ble.SetDefaultDevice(d)

    fmt.Println("Scanning for devices...")
    var foundDevices []*DeviceInfo
    deviceMap := make(map[string]bool) // Track seen devices by address

    err = ble.Scan(ctx, true, func(adv ble.Advertisement) {
        addr := adv.Addr().String()
        
        // Skip if we've already seen this device
        if deviceMap[addr] {
            return
        }
        
        if strings.HasPrefix(adv.LocalName(), "Yeti") {
            fmt.Printf("Found device: %s (%s) [Yeti]\n", adv.LocalName(), addr)
            foundDevices = append(foundDevices, &DeviceInfo{
                Address: addr,
                Name:    adv.LocalName(),
                Type:    "Yeti",
            })
            deviceMap[addr] = true
        } else if strings.HasPrefix(adv.LocalName(), "gz") {
            fmt.Printf("Found device: %s (%s) [gz]\n", adv.LocalName(), addr)
            foundDevices = append(foundDevices, &DeviceInfo{
                Address: addr,
                Name:    adv.LocalName(),
                Type:    "gz",
            })
            deviceMap[addr] = true
        } else if strings.HasPrefix(adv.LocalName(), "HT") {
            fmt.Printf("Found device: %s (%s) [Jackery]\n", adv.LocalName(), addr)
            foundDevices = append(foundDevices, &DeviceInfo{
                Address: addr,
                Name:    adv.LocalName(),
                Type:    "Jackery",
            })
            deviceMap[addr] = true
        }
    }, nil)

    if err != nil && err != context.DeadlineExceeded {
        return nil, fmt.Errorf("scan failed: %v", err)
    }

    if len(foundDevices) == 0 {
        return nil, fmt.Errorf("no compatible devices found")
    }

    return foundDevices, nil
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

func connectAndHandleGoalZero(ctx context.Context, deviceAddr string) error {
	client, err := ble.Dial(ctx, ble.NewAddr(deviceAddr))
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer client.CancelConnection()

	fmt.Printf("Connected to %s\n", deviceAddr)

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

	// Send command to initiate data transfer
	if err := client.WriteCharacteristic(txChar, []byte{0x00, 0x00, 0x00, 0x1a}, false); err != nil {
		return fmt.Errorf("failed to write to TX characteristic: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	if err := client.WriteCharacteristic(dataChar, []byte(`{"id":2,"method":"status"}`), false); err != nil {
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

	// Parse and display the relevant information
	var responseData struct {
		Result struct {
			Body struct {
				Batt  map[string]interface{} `json:"batt"`
				Ports map[string]interface{} `json:"ports"`
			} `json:"body"`
		} `json:"result"`
	}

	if err := json.Unmarshal(fullData, &responseData); err != nil {
		return fmt.Errorf("failed to parse response: %v", err)
	}

	battBytes, err := json.MarshalIndent(responseData.Result.Body.Batt, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling battery data: %v\n", err)
	} else {
		fmt.Printf("\nBattery info:\n%s\n", string(battBytes))
	}

	portsBytes, err := json.MarshalIndent(responseData.Result.Body.Ports, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling ports data: %v\n", err)
	} else {
		fmt.Printf("\nPorts info:\n%s\n", string(portsBytes))
	}

	return nil
}

// JackeryNotificationData holds the notification data from Jackery devices
type JackeryNotificationData struct {
	Data     []byte
	Complete bool
}

var jackeryResponseData string
var jackeryHitCount int = 0


func connectAndHandleJackery(ctx context.Context, deviceAddr string) error {
    client, err := ble.Dial(ctx, ble.NewAddr(deviceAddr))
    if err != nil {
        return fmt.Errorf("failed to connect: %v", err)
    }
    defer client.CancelConnection()

    fmt.Printf("Connected to Jackery device: %s\n", deviceAddr)

    // Exchange MTU for larger packet size
    if _, err := client.ExchangeMTU(512); err != nil {
        fmt.Printf("Warning: MTU exchange failed: %v\n", err)
    }

    // Find the Jackery service and characteristics
    ss, err := client.DiscoverServices(nil)
    if err != nil {
        return fmt.Errorf("failed to discover services: %v", err)
    }

    var writeChar, notifyChar *ble.Characteristic
    for _, s := range ss {
        cs, err := client.DiscoverCharacteristics(nil, s)
        if err != nil {
            continue
        }

        for _, c := range cs {
            cUUID := strings.ToLower(c.UUID.String())
            if strings.HasSuffix(cUUID, "ee01") {
                writeChar = c
            } else if strings.HasSuffix(cUUID, "ee02") {
                notifyChar = c
            }
        }
    }

    if writeChar == nil || notifyChar == nil {
        return fmt.Errorf("required characteristics not found")
    }

    // Set up notification handler
    responseChan := make(chan []byte, 10)
    defer close(responseChan)

    // Try to enable notifications by writing to CCCD
    fmt.Println("Attempting to enable notifications...")
    ds, err := client.DiscoverDescriptors(nil, notifyChar)
    if err != nil {
        fmt.Printf("Warning: Failed to discover descriptors: %v\n", err)
    } else {
        for _, d := range ds {
            if strings.HasSuffix(strings.ToLower(d.UUID.String()), "2902") {
                fmt.Println("Found CCCD descriptor, enabling notifications...")
                if err := client.WriteDescriptor(d, []byte{0x01, 0x00}); err != nil {
                    fmt.Printf("Warning: Failed to write to CCCD: %v\n", err)
                } else {
                    fmt.Println("Successfully enabled notifications via CCCD")
                }
                break
            }
        }
    }

    // Subscribe to notifications
    var collectedData []byte
    if err := client.Subscribe(notifyChar, false, func(data []byte) {
        fmt.Printf("Received notification: %x\n", data)
        responseChan <- data
        collectedData = append(collectedData, data...)
    }); err != nil {
        fmt.Printf("Warning: Failed to subscribe to notifications: %v\n", err)
    }

    // Send handshake command - this is the correct command for Jackery devices
    handshake := []byte{0x6d, 0xc7, 0x84, 0xb9, 0xd8, 0xa4, 0x48, 0xd5, 0x18}
    fmt.Printf("Sending handshake: %x\n", handshake)
    
    if err := client.WriteCharacteristic(writeChar, handshake, true); err != nil {
        return fmt.Errorf("handshake failed: %v", err)
    }

    // Wait for response with timeout
    fmt.Println("Waiting for response...")
    
    // Wait for enough data to be collected
    // Wait for enough data to be collected
    timeout := time.After(5 * time.Second)
    ticker := time.NewTicker(100 * time.Millisecond)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            if len(collectedData) > 0 {
                // Process all collected data
                fmt.Printf("Raw data received (%d bytes): %x\n", len(collectedData), collectedData)
                
                // Decrypt the data with RC4
                decrypted := DecryptJackery(defaultJackeryKey, collectedData)
                fmt.Printf("Decrypted data (%d bytes): %x\n", len(decrypted), decrypted)
                
                // Print hex representation for debugging
                fmt.Println("\nHex dump of decrypted data:")
                for i := 0; i < len(decrypted); i += 16 {
                    end := i + 16
                    if end > len(decrypted) {
                        end = len(decrypted)
                    }
                    chunk := decrypted[i:end]
                    
                    // Print hex values
                    hexStr := ""
                    for _, b := range chunk {
                        hexStr += fmt.Sprintf("%02x ", b)
                    }
                    
                    // Print ASCII representation
                    asciiStr := ""
                    for _, b := range chunk {
                        if b >= 32 && b <= 126 { // Printable ASCII
                            asciiStr += string(b)
                        } else {
                            asciiStr += "."
                        }
                    }
                    
                    fmt.Printf("%04x: %-48s %s\n", i, hexStr, asciiStr)
                }
                
                // Try multiple known Jackery formats
                
                // Format 1: Common in newer models
                // Data starts at byte 16, XOR key at end-3
                if len(decrypted) > 20 {
                    fmt.Println("\nTrying Format 1 (newer models)...")
                    payload := decrypted[16:]
                    
                    // Try each byte as a potential XOR key
                    for i := 0; i < 10; i++ {
                        if len(decrypted) <= i {
                            break
                        }
                        
                        potentialKey := decrypted[len(decrypted)-1-i]
                        fmt.Printf("Trying XOR key 0x%02x (from end-%d)\n", potentialKey, i+1)
                        
                        decoded := make([]byte, len(payload))
                        for j, b := range payload {
                            decoded[j] = b ^ potentialKey
                        }
                        
                        // Check if resulting data has JSON format
                        jsonStart := -1
                        jsonEnd := -1
                        
                        for j := 0; j < len(decoded); j++ {
                            if decoded[j] == '{' {
                                jsonStart = j
                                break
                            }
                        }
                        
                        if jsonStart >= 0 {
                            bracketCount := 1
                            for j := jsonStart + 1; j < len(decoded); j++ {
                                if decoded[j] == '{' {
                                    bracketCount++
                                } else if decoded[j] == '}' {
                                    bracketCount--
                                    if bracketCount == 0 {
                                        jsonEnd = j
                                        break
                                    }
                                }
                            }
                            
                            if jsonEnd > jsonStart {
                                jsonData := decoded[jsonStart:jsonEnd+1]
                                if isValidJSON(string(jsonData)) {
                                    fmt.Printf("\n=== Valid JSON Found (Format 1, key=0x%02x) ===\n", potentialKey)
                                    prettyPrint(string(jsonData))
                                    return nil
                                }
                            }
                        }
                    }
                }
                
                // Format 2: Used in some older models
                // Try direct string search in decrypted data
                fmt.Println("\nTrying direct JSON search in decrypted data...")
                for i := 0; i < len(decrypted); i++ {
                    if decrypted[i] == '{' {
                        bracketCount := 1
                        for j := i + 1; j < len(decrypted); j++ {
                            if decrypted[j] == '{' {
                                bracketCount++
                            } else if decrypted[j] == '}' {
                                bracketCount--
                                if bracketCount == 0 {
                                    jsonCandidate := string(decrypted[i:j+1])
                                    fmt.Printf("Found potential JSON: %s\n", jsonCandidate)
                                    
                                    if isValidJSON(jsonCandidate) {
                                        fmt.Println("\n=== Valid JSON Found (direct search) ===")
                                        prettyPrint(jsonCandidate)
                                        return nil
                                    }
                                    break
                                }
                            }
                        }
                    }
                }
                
                // Format 3: Special handling for specific model
                // Some Jackery devices use a different packet format
                fmt.Println("\nTrying alternate method (fixed header, byte-by-byte XOR)...")
                if len(decrypted) > 20 {
                    // Skip first 20 bytes (header)
                    actualData := decrypted[20:]
                    
                    // Try each byte near the end as key
                    for offset := 1; offset <= 5; offset++ {
                        if len(decrypted) <= offset {
                            continue
                        }
                        
                        key := decrypted[len(decrypted)-offset]
                        result := make([]byte, len(actualData))
                        for i, b := range actualData {
                            result[i] = b ^ key
                        }
                        
                        // Look for readable data
                        ascii := string(result)
                        fmt.Printf("Key 0x%02x (end-%d): %s\n", key, offset, truncateString(ascii, 40))
                        
                        if strings.Contains(ascii, "{") && strings.Contains(ascii, "}") {
                            // Extract JSON part
                            start := strings.Index(ascii, "{")
                            end := strings.LastIndex(ascii, "}")
                            if start < end {
                                jsonPart := ascii[start:end+1]
                                if isValidJSON(jsonPart) {
                                    fmt.Println("\n=== Valid JSON Found (Format 3) ===")
                                    prettyPrint(jsonPart)
                                    return nil
                                }
                            }
                        }
                    }
                }
                
                fmt.Println("\nCould not extract valid data in any known format.")
                fmt.Println("Trying to decode the raw data as text:")
                
                // Print as ASCII for manual inspection
                fmt.Println(string(decrypted))
                
                return nil
            }
        case <-timeout:
            return fmt.Errorf("timeout waiting for data")
        case <-ctx.Done():
            return fmt.Errorf("operation canceled")
        }
    }
}

// Helper function to truncate string for display
func truncateString(s string, maxLen int) string {
    if len(s) <= maxLen {
        return s
    }
    return s[:maxLen] + "..."
}

// Helper functions
func isValidJSON(s string) bool {
    var js interface{}
    return json.Unmarshal([]byte(s), &js) == nil
}

func prettyPrint(jsonStr string) {
    var data interface{}
    if err := json.Unmarshal([]byte(jsonStr), &data); err == nil {
        pretty, _ := json.MarshalIndent(data, "", "  ")
        fmt.Printf("\n=== Formatted Jackery Data ===\n%s\n", string(pretty))
    }
}

func main() {
	scanCtx, scanCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer scanCancel()

	devices, err := scanForDevices(scanCtx)
	if err != nil {
		log.Fatalf("Error scanning for devices: %v", err)
	}

	fmt.Println("\n**************** Battery Monitoring for Jackery and Goal Zero *******************")
	fmt.Println("Please pick a device to monitor from the available devices:")
	
	for i, device := range devices {
		fmt.Printf("%d- %s %s [%s]\n", i+1, device.Type, device.Name, device.Address)
	}

	var choice int
	fmt.Print("> ")
	_, err = fmt.Scanf("%d", &choice)
	if err != nil || choice < 1 || choice > len(devices) {
		log.Fatalf("Invalid selection. Please enter a number between 1 and %d", len(devices))
	}

	selectedDevice := devices[choice-1]
	fmt.Printf("Selected device: %s (%s)\n", selectedDevice.Name, selectedDevice.Address)

	for {
		connCtx, connCancel := context.WithTimeout(context.Background(), 60*time.Second)
		
		var err error
		switch selectedDevice.Type {
		case "Yeti":
			err = connectAndHandleYeti(connCtx, selectedDevice.Address)
		case "gz":
			err = connectAndHandleGoalZero(connCtx, selectedDevice.Address)
		case "Jackery":
			err = connectAndHandleJackery(connCtx, selectedDevice.Address)
		default:
			log.Fatalf("Unknown device type: %s", selectedDevice.Type)
		}
		
		if err != nil {
			log.Printf("Error: %v\n", err)
		}
		
		connCancel()
		
		fmt.Println("\nWaiting 30 seconds before next attempt...")
		time.Sleep(30 * time.Second)
	}
}