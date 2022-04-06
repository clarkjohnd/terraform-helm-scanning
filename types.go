package main

import "time"

// Generated with JSON to Go VS Code Package

type TrivyScan struct {
	SchemaVersion int       `json:"SchemaVersion"`
	ArtifactName  string    `json:"ArtifactName"`
	ArtifactType  string    `json:"ArtifactType"`
	Metadata      Metadata  `json:"Metadata"`
	Results       []Results `json:"Results"`
}
type Os struct {
	Family string `json:"Family"`
	Name   string `json:"Name"`
}
type History struct {
	Created    time.Time `json:"created"`
	CreatedBy  string    `json:"created_by"`
	EmptyLayer bool      `json:"empty_layer,omitempty"`
	Comment    string    `json:"comment,omitempty"`
}
type Rootfs struct {
	Type    string   `json:"type"`
	DiffIds []string `json:"diff_ids"`
}
type Config struct {
	Entrypoint []string `json:"Entrypoint"`
	Env        []string `json:"Env"`
}
type ImageConfig struct {
	Architecture string    `json:"architecture"`
	Created      time.Time `json:"created"`
	History      []History `json:"history"`
	Os           string    `json:"os"`
	Rootfs       Rootfs    `json:"rootfs"`
	Config       Config    `json:"config"`
}
type Metadata struct {
	Os          Os          `json:"OS"`
	ImageID     string      `json:"ImageID"`
	DiffIDs     []string    `json:"DiffIDs"`
	RepoDigests []string    `json:"RepoDigests"`
	ImageConfig ImageConfig `json:"ImageConfig"`
}
type Layer struct {
	DiffID string `json:"DiffID"`
}
type DataSource struct {
	ID   string `json:"ID"`
	Name string `json:"Name"`
	URL  string `json:"URL"`
}
type Nvd struct {
	V2Vector string  `json:"V2Vector"`
	V3Vector string  `json:"V3Vector"`
	V2Score  int     `json:"V2Score"`
	V3Score  float64 `json:"V3Score"`
}
type Redhat struct {
	V3Vector string  `json:"V3Vector"`
	V3Score  float64 `json:"V3Score"`
}
type Cvss struct {
	Nvd    Nvd    `json:"nvd"`
	Redhat Redhat `json:"redhat"`
}
type Vulnerabilities struct {
	VulnerabilityID  string     `json:"VulnerabilityID"`
	PkgName          string     `json:"PkgName"`
	InstalledVersion string     `json:"InstalledVersion"`
	FixedVersion     string     `json:"FixedVersion"`
	Layer            Layer      `json:"Layer"`
	SeveritySource   string     `json:"SeveritySource"`
	PrimaryURL       string     `json:"PrimaryURL"`
	DataSource       DataSource `json:"DataSource"`
	Title            string     `json:"Title"`
	Description      string     `json:"Description"`
	Severity         string     `json:"Severity"`
	CweIDs           []string   `json:"CweIDs"`
	Cvss             Cvss       `json:"CVSS"`
	References       []string   `json:"References"`
	PublishedDate    time.Time  `json:"PublishedDate"`
	LastModifiedDate time.Time  `json:"LastModifiedDate"`
}
type Results struct {
	Target          string            `json:"Target"`
	Class           string            `json:"Class"`
	Type            string            `json:"Type"`
	Vulnerabilities []Vulnerabilities `json:"Vulnerabilities,omitempty"`
}

type Image struct {
	Registry string `yaml:"registry,omitempty"`
	Name     string `yaml:"name"`
	RawName  string `yaml:"-"`
	Digests  struct {
		Amd64 string `yaml:"amd64"`
		Arm64 string `yaml:"arm64"`
	} `yaml:"digests"`
	Policy ImagePolicy
}

type ImagePolicy struct {
	Name     string   `yaml:"name"`
	Levels   []string `yaml:"severityLevels"`
	Accepted []struct {
		CVE    string `yaml:"cve"`
		Reason string `yaml:"reason"`
	} `yaml:"acceptedSeverities"`
	IgnoreUnfixed bool `yaml:"ignoreUnfixed"`
}
