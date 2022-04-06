package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"reflect"
	"strings"

	"gopkg.in/yaml.v2"
)

var workingDir string
var rulesPath string
var imagePath string
var exitFail bool

// var trivyText string

func main() {

	exitFail = false

	// Set global
	workingDir = os.Getenv("WORKING_DIRECTORY")
	rulesFile := os.Getenv("RULES_FILE")
	imageFile := os.Getenv("IMAGE_FILE")

	// Environmental variable defaults
	if len(workingDir) == 0 {
		workingDir = "/github/workspace"
	}

	if len(rulesFile) == 0 {
		rulesFile = "security_rules.yaml"
	}

	if len(imageFile) == 0 {
		imageFile = "images.yaml"
	}

	// Define paths to files
	rulesPath = workingDir + "/" + rulesFile
	imagePath = workingDir + "/" + imageFile

	// trivyText = "# Trivy Scan Results\n\n"
	// trivyJson = `{\n\t"scans":[`

	// Run the image scanning
	imageScan()

	// Exit status dependent on unaccepted severities being found
	if exitFail {
		log.Print("Unexpected severity found.")
		os.Exit(1)
	}
	os.Exit(0)

}

func imageScan() {

	var trivyScans []TrivyScan

	// Read the security rules YAML file
	log.Printf("Opening file from %s...", rulesPath)
	rulesYaml, err := os.ReadFile(rulesPath)

	if err != nil {
		if strings.Contains(err.Error(), "no such file or directory") {
			// Handle no rules file existing
			log.Print("No security rules found, proceeding with defaults.")
		} else {
			check(err)
		}
	}

	MultilineLog(string(rulesYaml))

	// Read the security rules YAML file
	log.Printf("Opening file from %s...", imagePath)
	imageYaml, err := os.ReadFile(imagePath)
	check(err)
	MultilineLog(string(imageYaml))

	var imagePolicies []ImagePolicy
	var images []Image

	yaml.UnmarshalStrict(rulesYaml, &imagePolicies)
	yaml.UnmarshalStrict(imageYaml, &images)

	var imagesWithPolicies []Image

	// Link image data to security rules by image name
	for _, image := range images {

		policyFound := false

		for _, imagePolicy := range imagePolicies {

			// Check to see if imagePolicy matches the image
			// if so, append the image with policy to imagesWithPolicies
			if image.Name == imagePolicy.Name {
				// Convert severities to uppercase
				for i, level := range imagePolicy.Levels {
					imagePolicy.Levels[i] = strings.ToUpper(level)
				}
				if len(imagePolicy.Levels) == 0 {
					imagePolicy.Levels = []string{"MEDIUM", "HIGH", "CRITICAL"}
				}
				image.Policy = imagePolicy
				policyFound = true
				break
			}
		}

		// Set defaults if no policy given
		if !policyFound {
			image.Policy = ImagePolicy{
				Name:   image.Name,
				Levels: []string{"MEDIUM", "HIGH", "CRITICAL"},
			}
		}

		imagesWithPolicies = append(imagesWithPolicies, image)

	}

	for _, image := range imagesWithPolicies {

		// Collect architecture types
		fields := reflect.TypeOf(image.Digests)
		values := reflect.ValueOf(image.Digests)
		num := fields.NumField()

		shortName := image.Name

		// Set title of image
		// trivyText += fmt.Sprintf("---\n## %s \n", shortName)

		// For architecture type:
		for i := 0; i < num; i++ {

			fullImageName := ""

			if image.Registry != "" {
				fullImageName += image.Registry + "/"
			}

			fullImageName += image.Name + "@" + values.Field(i).String()

			arch := fields.Field(i).Name

			trivyScan := trivyScan(fullImageName, shortName, arch, image)

			trivyScans = append(trivyScans, trivyScan)

		}

	}

	trivyJson, err := json.Marshal(trivyScans)
	check(err)

	Command(fmt.Sprintf(`echo "::set-output name=trivy::%s"`, trivyJson), "", false)

	// Log text output of scans
	// markdownTrivyFile := workingDir + "/trivytext.md"
	// err = os.WriteFile(markdownTrivyFile, []byte(trivyText), 0666)
	// check(err)
}

// Run Trivy Scan
func trivyScan(imageName string, shortName string, arch string, image Image) (trivyScan TrivyScan) {
	MultilineLog(fmt.Sprintf("-----\nTrivy scanning image: %s, architecture: %s\n-----", imageName, arch))

	joinedLevels := strings.Join(image.Policy.Levels, ",")

	if len(image.Policy.Accepted) > 0 {

		var acceptedSeverities []string
		log.Print("Accepted severities:")
		for _, cve := range image.Policy.Accepted {
			acceptedSeverities = append(acceptedSeverities, cve.CVE)
			log.Print(fmt.Sprintf("- %s: %s", cve.CVE, cve.Reason))
		}

		joinedAccepted := strings.Join(acceptedSeverities, "\n")

		trivyIgnoreFile := workingDir + "/.trivyignore"

		log.Print("Writing accepted severities to .trivyignore")
		err := os.WriteFile(trivyIgnoreFile, []byte(joinedAccepted), 0666)
		check(err)

		// Have to remove .trivyignore each time in case next image has no ignores
		defer removeTrivyIgnore(trivyIgnoreFile)

	}

	tempJsonFile := workingDir + "/.temptrivy.json"

	// Scan and collect results in JSON format
	log.Print("Running Trivy scan (JSON format)...")
	Command(
		fmt.Sprintf("trivy image -s %s -f json -o %s %s", joinedLevels, tempJsonFile, imageName),
		workingDir,
		true,
	)

	// Scan and collect results in text format for Markdown
	// log.Print("Running Trivy scan (text format)...")
	// trivyText += fmt.Sprintf("### %s\n---\n", arch)
	// trivyText += string(Command(fmt.Sprintf("trivy image -s %s %s", joinedLevels, imageName), workingDir))

	// Read JSON results back into application
	trivyJson, err := os.ReadFile(tempJsonFile)
	check(err)

	json.Unmarshal(trivyJson, &trivyScan)

	// Check for any vulnerabilities being present and set exit error if so
	for _, result := range trivyScan.Results {
		if len(result.Vulnerabilities) > 0 {
			exitFail = true
		}
	}

	return

}

// Used with Defer to delete .trivyignore files
func removeTrivyIgnore(file string) {
	log.Print("Removing .trivyignore file")
	err := os.Remove(file)
	check(err)
}

// A function to split and log multiline strings.
func MultilineLog(input string) {

	lines := strings.Split(input, "\n")

	for _, line := range lines {
		log.Print(line)
	}
}

// A function to run a command by string in a specific working directory
// with stdout and stderr logging and error checks.
func Command(inputString string, dir string, showStdout bool) []byte {

	MultilineLog(fmt.Sprintf("$ %s", inputString))

	quoted := false
	input := strings.FieldsFunc(inputString, func(r rune) bool {
		if r == '"' {
			quoted = !quoted
		}
		return !quoted && r == ' '
	})

	for i, s := range input {
		input[i] = strings.Trim(s, `"`)
	}

	cmd := exec.Command(
		input[0], input[1:]...,
	)

	if dir != "" || len(dir) > 0 {
		cmd.Dir = dir
	}

	var out bytes.Buffer
	var stderr bytes.Buffer

	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()

	if err != nil {
		MultilineLog(fmt.Sprint(err) + ": " + stderr.String())
		log.Fatal(err)
	}

	if showStdout {
		MultilineLog("Result:\n" + out.String())
	}

	return out.Bytes()
}

// Simple function to check errors.
func check(err error) {
	if err != nil {
		MultilineLog(err.Error())
		log.Fatal(err)
	}
}
