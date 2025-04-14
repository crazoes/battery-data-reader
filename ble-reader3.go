package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"strings"
	"time"
	"strconv"

	"github.com/go-ble/ble"
	"github.com/go-ble/ble/examples/lib/dev"
	"crypto/rc4"
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

func DecryptJackery(key string, data []byte) ([]byte, error) {
	cipher, err := rc4.NewCipher([]byte(key))
	if err != nil {
		log.Printf("Error creating RC4 cipher: %v", err)
		return nil, err
	}
	
	decrypted := make([]byte, len(data))
	cipher.XORKeyStream(decrypted, data)
	return decrypted, nil
} 

func DecryptJackeryAndDecode(key string, data []byte) string {
	decrypted, err := DecryptJackery(key, data)
	if err != nil {
		return ""
	}

	if len(decrypted) < 13 { // Need at least 10 bytes prefix + some data + 3 bytes suffix
		return ""
	}

	xorValue := decrypted[len(decrypted) - 3]
	decoded := make([]byte, len(decrypted) - 10 - 3)
	for i, v := range decrypted[10:len(decrypted) - 3] {
		decoded[i] = v ^ xorValue
	}
	return string(decoded)
}

var key string
var deviceAddr string

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

		if strings.HasPrefix(adv.LocalName(), "HT") {
			srvDatas := adv.ServiceData()
			if len(srvDatas) == 0 {
				return
			}
			
			srvData := srvDatas[0]
			mfd := adv.ManufacturerData()
			if len(mfd) < 2 {
				return
			}

			smfd := string(mfd[2:])
			atoi, err := strconv.Atoi(string(smfd[:2]))
			if err != nil {
				return
			}

			// Prepare encryption key
			key = string(atoi) + smfd[:2] + smfd[len(smfd) - 5:] + "LYx*G!6u9#"
			data, err := DecryptJackery(key, srvData.Data)
			if err != nil {
				return
			}
			
			if len(data) <= 8 { // Need at least some data for XOR
				return
			}
			
			xorValue := data[len(data) - 3]

			keyBytes := ""
			for _, x := range data[2:8] {
				keyBytes += string(x ^ xorValue)
			}
			key = smfd[len(smfd)-6:] + keyBytes + defaultJackeryKey
		}
		
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

// Data structures for device states
type GoalZeroState struct {
	Batt struct {
		SOC   int     `json:"soc"`
		MTEF  int     `json:"mTtef"`
		V     float64 `json:"v"`
		CTMP  float64 `json:"cTmp"`
	} `json:"batt"`
	Ports map[string]struct {
		W int `json:"w"`
		S int `json:"s"`
	} `json:"ports"`
}

// Function to read data from a Yeti device (single read)
func readYetiData(client ble.Client, dataChar, txChar *ble.Characteristic) error {
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
				State json.RawMessage `json:"state"`
				Ports map[string]struct {
					W int `json:"w"`
					S int `json:"s"`
				} `json:"ports"`
			} `json:"body"`
		} `json:"result"`
	}

	if err := json.Unmarshal(fullData, &responseData); err != nil {
		return fmt.Errorf("failed to parse response: %v", err)
	}

	// Parse the state JSON string
	var batteryState struct {
		SOC  int     `json:"soc"`
		MTEF int     `json:"mTtef"`
		V    float64 `json:"v"`
		CTMP float64 `json:"cTmp"`
	}

	if err := json.Unmarshal(responseData.Result.Body.State, &batteryState); err != nil {
		return fmt.Errorf("failed to parse battery state: %v", err)
	}

	// Extract port information
	ports := responseData.Result.Body.Ports
	acIn := ports["acIn"].W
	acOut := ports["acOut"].W
	v12Out := ports["v12Out"].W
	usbOut := ports["usbOut"].W
	
	// Extract switch states
	usbSwitch := 0
	if ports["usbOut"].S > 0 {
		usbSwitch = 1
	}
	v12OutSwitch := 0
	if ports["v12Out"].S > 0 {
		v12OutSwitch = 1
	}
	acSwitch := 0
	if ports["acOut"].S > 0 {
		acSwitch = 1
	}

	// Format output similar to Python version
	fmt.Printf("soc: %d%%\n", batteryState.SOC)
	fmt.Printf("Power In: %d\n", acIn)
	fmt.Printf("Power Out: %d\n", acOut)
	fmt.Printf("runtime remaining: %dH\n", int(math.Ceil(math.Abs(float64(batteryState.MTEF))/60)))
	fmt.Printf("model: YETI\n")
	fmt.Printf("mac: %s\n", deviceAddr)
	
	acStatus := "off"
	if acSwitch == 1 {
		acStatus = "on"
	}
	fmt.Printf("ac %s watt draw: (input: %d), (output: %d)\n", acStatus, acIn, acOut)
	
	usbStatus := "off"
	if usbSwitch == 1 {
		usbStatus = "on"
	}
	fmt.Printf("usb %s watt draw: %d\n", usbStatus, usbOut)
	
	v12Status := "off"
	if v12OutSwitch == 1 {
		v12Status = "on"
	}
	fmt.Printf("v12out %s watt draw: %d\n", v12Status, v12Out)
	
	fmt.Printf("voltage: %.2fV\n", batteryState.V)
	fmt.Printf("temperature: %.2f F\n", batteryState.CTMP*9/5+32)

	return nil
}

// Function to read data from a Goal Zero device (single read)
func readGoalZeroData(client ble.Client, dataChar, txChar *ble.Characteristic) error {
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
	var fullData []byte
	maxReadAttempts := 5

	for i := 0; i < maxReadAttempts; i++ {
		dataPart, err := client.ReadCharacteristic(dataChar)
		if err != nil {
			fmt.Printf("Read failed (attempt %d): %v\n", i+1, err)
			continue
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
				Batt struct {
					SOC   int     `json:"soc"`
					MTEF  int     `json:"mTtef"`
					V     float64 `json:"v"`
					CTMP  float64 `json:"cTmp"`
				} `json:"batt"`
				Ports map[string]struct {
					W int `json:"w"`
					S int `json:"s"`
				} `json:"ports"`
			} `json:"body"`
		} `json:"result"`
	}

	if err := json.Unmarshal(fullData, &responseData); err != nil {
		return fmt.Errorf("failed to parse response: %v", err)
	}

	// Extract port information
	ports := responseData.Result.Body.Ports
	acIn := ports["acIn"].W
	acOut := ports["acOut"].W
	v12Out := ports["v12Out"].W
	usbOut := ports["usbOut"].W
	
	// Extract switch states
	usbSwitch := 0
	if ports["usbOut"].S > 0 {
		usbSwitch = 1
	}
	v12OutSwitch := 0
	if ports["v12Out"].S > 0 {
		v12OutSwitch = 1
	}
	acSwitch := 0
	if ports["acOut"].S > 0 {
		acSwitch = 1
	}

	// Format output similar to Python version
	batt := responseData.Result.Body.Batt
	fmt.Printf("soc: %d%%\n", batt.SOC)
	fmt.Printf("Power In: %d\n", acIn)
	fmt.Printf("Power Out: %d\n", acOut)
	fmt.Printf("runtime remaining: %dH\n", int(math.Ceil(math.Abs(float64(batt.MTEF))/60)))
	fmt.Printf("model: goalzero\n")
	fmt.Printf("mac: %s\n", deviceAddr)
	
	acStatus := "off"
	if acSwitch == 1 {
		acStatus = "on"
	}
	fmt.Printf("ac %s watt draw: (input: %d), (output: %d)\n", acStatus, acIn, acOut)
	
	usbStatus := "off"
	if usbSwitch == 1 {
		usbStatus = "on"
	}
	fmt.Printf("usb %s watt draw: %d\n", usbStatus, usbOut)
	
	v12Status := "off"
	if v12OutSwitch == 1 {
		v12Status = "on"
	}
	fmt.Printf("v12out %s watt draw: %d\n", v12Status, v12Out)
	
	fmt.Printf("voltage: %.2fV\n", batt.V)
	fmt.Printf("temperature: %.2f F\n", batt.CTMP*9/5+32)

	return nil
}

// JackeryNotificationData holds the notification data from Jackery devices
type JackeryNotificationData struct {
	Data     []byte
	Complete bool
}

var jackeryResponseData string
var jackeryHitCount int = 0

// Notification handler for Jackery devices
func jackeryNotificationHandler(data []byte) {
	decrypted, err := DecryptJackery(key, data)
	if err != nil {
		log.Printf("Decryption error: %v", err)
		return
	}
	
	if len(decrypted) < 13 { // Need at least 10 bytes prefix + some data + 3 bytes suffix
		return
	}
	
	xorValue := decrypted[len(decrypted)-3]
	decoded := make([]byte, 0, len(decrypted)-13)
	
	for _, x := range decrypted[10:len(decrypted)-3] {
		decoded = append(decoded, x^xorValue)
	}
	
	// Append decoded data
	jackeryResponseData += string(decoded)
	
	// Increment counter after processing
	jackeryHitCount++
	
	// Process data after receiving enough notifications
	if jackeryHitCount >= 2 {
		var response struct {
			RB   int     `json:"rb"`  // Battery percentage
			IP   int     `json:"ip"`  // Input power
			OP   int     `json:"op"`  // Output power
			ACIP int     `json:"acip"` // AC input
			IT   int     `json:"it"`  // Input total
			OT   int     `json:"ot"`  // Output total
			ACOV int     `json:"acov"` // AC output voltage
			BT   float64 `json:"bt"`  // Battery temperature
		}
		
		err := json.Unmarshal([]byte(jackeryResponseData), &response)
		if err != nil {
			log.Printf("Failed to parse Jackery data: %v", err)
			return
		}
		
		// Format output similar to Python version
		runtimeHours := math.Ceil(float64(response.RB) * 16.43 / 100)
		
		fmt.Printf("soc: %d%%\n", response.RB)
		fmt.Printf("Power In: %d\n", response.IP)
		fmt.Printf("Power Out: %d\n", response.OP)
		fmt.Printf("runtime remaining: %dH\n", int(runtimeHours))
		fmt.Printf("model: HT Jackery\n")
		fmt.Printf("mac: %s\n", deviceAddr)
		
		acStatus := "off"
		if response.ACIP > 0 {
			acStatus = "on"
		}
		fmt.Printf("ac %s watt draw: (input: %.1f), (output: %.1f)\n", 
			acStatus, float64(response.IT)/10, float64(response.OT)/10)
		
		fmt.Printf("voltage: %.2f\n", float64(response.ACOV)/100)
		fmt.Printf("temperature: %.1f Celsius\n", response.BT/10)
	}
}

// Function to read data from a Jackery device
func readJackeryData(client ble.Client, writeChar *ble.Characteristic) error {
	// Reset notification variables
	jackeryResponseData = ""
	jackeryHitCount = 0
	
	// Send handshake command
	handshake := []byte{0x6d, 0xc7, 0x84, 0xb9, 0xd8, 0xa4, 0x48, 0xd5, 0x18}
	if err := client.WriteCharacteristic(writeChar, handshake, true); err != nil {
		return fmt.Errorf("handshake failed: %v", err)
	}

	// Wait for notifications to be processed
	// A longer timeout to ensure we receive enough notifications
	timeout := time.After(10 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Check if we've received and processed notifications
			if jackeryHitCount >= 2 {
				// Give a little time for processing to complete
				time.Sleep(200 * time.Millisecond)
				return nil
			}
		case <-timeout:
			// If we've received some data but not enough, don't fail
			if jackeryHitCount > 0 || jackeryResponseData != "" {
				fmt.Println("Received partial data, continuing...")
				return nil
			}
			return fmt.Errorf("timeout waiting for data")
		}
	}
}

func connectToYeti(ctx context.Context, deviceAddr string) error {
	client, err := ble.Dial(ctx, ble.NewAddr(deviceAddr))
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	
	fmt.Printf("Connected to %s\n", deviceAddr)

	// Exchange MTU for larger packet size
	if _, err := client.ExchangeMTU(256); err != nil {
		fmt.Printf("Warning: MTU exchange failed: %v\n", err)
	}

	// Discover services
	ss, err := client.DiscoverServices(nil)
	if err != nil {
		client.CancelConnection()
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
		client.CancelConnection()
		return fmt.Errorf("RPC service not found")
	}

	// Discover characteristics
	cs, err := client.DiscoverCharacteristics(nil, rpcService)
	if err != nil {
		client.CancelConnection()
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
		client.CancelConnection()
		return fmt.Errorf("missing required characteristics")
	}

	// Main monitoring loop - maintain one connection
	for {
		err := readYetiData(client, dataChar, txChar)
		if err != nil {
			client.CancelConnection()
			return fmt.Errorf("error reading data: %v", err)
		}
		
		fmt.Println("\nWaiting 2 seconds before next read...")
		time.Sleep(2 * time.Second)
	}
}

func connectToGoalZero(ctx context.Context, deviceAddr string) error {
	client, err := ble.Dial(ctx, ble.NewAddr(deviceAddr))
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	
	fmt.Printf("Connected to %s\n", deviceAddr)

	// Exchange MTU first
	if _, err := client.ExchangeMTU(512); err != nil {
		fmt.Printf("Warning: MTU exchange failed: %v\n", err)
	}
	time.Sleep(500 * time.Millisecond)

	// Discover all services
	ss, err := client.DiscoverServices(nil)
	if err != nil {
		client.CancelConnection()
		return fmt.Errorf("failed to discover services: %v", err)
	}

	// Find the RPC service by UUID prefix (without hyphens)
	var rpcService *ble.Service
	targetServiceUUID := "5f6d4f535f5250435f5356435f49445f"
	for _, s := range ss {
		if strings.ToLower(s.UUID.String()) == targetServiceUUID {
			rpcService = s
			break
		}
	}

	if rpcService == nil {
		client.CancelConnection()
		return fmt.Errorf("RPC service not found (looking for UUID %s)", targetServiceUUID)
	}

	// Discover all characteristics in the RPC service
	cs, err := client.DiscoverCharacteristics(nil, rpcService)
	if err != nil {
		client.CancelConnection()
		return fmt.Errorf("failed to discover characteristics: %v", err)
	}

	// Find required characteristics by their full UUIDs (without hyphens)
	var dataChar, rxChar, txChar *ble.Characteristic
	for _, c := range cs {
		cUUID := strings.ToLower(c.UUID.String())
		switch cUUID {
		case "5f6d4f535f5250435f646174615f5f5f": // DATA
			dataChar = c
		case "5f6d4f535f5250435f72785f63746c5f": // RX
			rxChar = c
		case "5f6d4f535f5250435f74785f63746c5f": // TX
			txChar = c
		}
	}

	if dataChar == nil {
		client.CancelConnection()
		return fmt.Errorf("DATA characteristic not found")
	}
	if rxChar == nil {
		client.CancelConnection()
		return fmt.Errorf("RX characteristic not found")
	}
	if txChar == nil {
		client.CancelConnection()
		return fmt.Errorf("TX characteristic not found")
	}

	// Main monitoring loop - maintain one connection
	for {
		err := readGoalZeroData(client, dataChar, txChar)
		if err != nil {
			client.CancelConnection()
			return fmt.Errorf("error reading data: %v", err)
		}
		
		fmt.Println("\nWaiting 2 seconds before next read...")
		time.Sleep(2 * time.Second)
	}
}

func connectToJackery(ctx context.Context, deviceAddr string) error {
	client, err := ble.Dial(ctx, ble.NewAddr(deviceAddr))
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}

	fmt.Printf("Connected to Jackery device: %s\n", deviceAddr)

	// Exchange MTU for larger packet size
	if _, err := client.ExchangeMTU(512); err != nil {
		fmt.Printf("Warning: MTU exchange failed: %v\n", err)
	}

	// Find the Jackery service and characteristics
	ss, err := client.DiscoverServices(nil)
	if err != nil {
		client.CancelConnection()
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
		client.CancelConnection()
		return fmt.Errorf("required characteristics not found")
	}

	// Enable notifications
	ds, err := client.DiscoverDescriptors(nil, notifyChar)
	if err != nil {
		fmt.Printf("Warning: Failed to discover descriptors: %v\n", err)
	} else {
		for _, d := range ds {
			if strings.HasSuffix(strings.ToLower(d.UUID.String()), "2902") {
				if err := client.WriteDescriptor(d, []byte{0x01, 0x00}); err != nil {
					fmt.Printf("Warning: Failed to write to CCCD: %v\n", err)
				}
				break
			}
		}
	}

	// Subscribe to notifications
	if err := client.Subscribe(notifyChar, false, func(data []byte) {
		jackeryNotificationHandler(data)
	}); err != nil {
		client.CancelConnection()
		return fmt.Errorf("failed to subscribe to notifications: %v", err)
	}

	// Main monitoring loop - maintain one connection
	for {
		err := readJackeryData(client, writeChar)
		if err != nil {
			client.CancelConnection()
			return fmt.Errorf("error reading data: %v", err)
		}
		
		// Reset counters for next read
		jackeryHitCount = 0
		jackeryResponseData = ""
		
		fmt.Println("\nWaiting 2 seconds before next read...")
		time.Sleep(2 * time.Second)
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
	deviceAddr = selectedDevice.Address

	// Create a long-lived context for the connection
	connCtx := context.Background()

	// Connect once and keep reading data in a loop
	var connErr error
	switch selectedDevice.Type {
	case "Yeti":
		connErr = connectToYeti(connCtx, deviceAddr)
	case "gz":
		connErr = connectToGoalZero(connCtx, deviceAddr)
	case "Jackery":
		connErr = connectToJackery(connCtx, deviceAddr)
	default:
		log.Fatalf("Unknown device type: %s", selectedDevice.Type)
	}
	
	if connErr != nil {
		log.Fatalf("Error in device connection: %v", connErr)
	}
}