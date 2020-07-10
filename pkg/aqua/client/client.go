package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

var ErrNotFound = errors.New("not found")

type client struct {
	baseURL    string
	username   string
	password   string
	httpClient *http.Client
}

func (c *client) newGetRequest(url string) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json; charset=UTF-8")
	req.SetBasicAuth(c.username, c.password)
	return req, nil
}

type Clientset interface {
	Registries() RegistriesInterface
	Images() ImagesInterface
}

type ImagesInterface interface {
	Vulnerabilities(registry, repo, tag string) (VulnerabilitiesResponse, error)
}

type RegistriesInterface interface {
	List() ([]RegistryResponse, error)
}

type Client struct {
	registries *Registries
	images     *Images
}

type Authorization struct {
	Basic *UsernameAndPassword
}

type UsernameAndPassword struct {
	Username string
	Password string
}

func NewClient(baseURL string, authorization Authorization) *Client {
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}
	client := &client{
		baseURL:    baseURL,
		username:   authorization.Basic.Username,
		password:   authorization.Basic.Password,
		httpClient: httpClient,
	}

	return &Client{
		images: &Images{
			client: client,
		},
		registries: &Registries{
			client: client,
		},
	}
}

func (c *Client) Images() ImagesInterface {
	return c.images
}

func (c *Client) Registries() RegistriesInterface {
	return c.registries
}

type Images struct {
	client *client
}

func (i *Images) Vulnerabilities(registry, repo, tag string) (VulnerabilitiesResponse, error) {
	url := fmt.Sprintf("%s/api/v2/images/%s/%s/%s/vulnerabilities", i.client.baseURL, registry, repo, tag)

	req, err := i.client.newGetRequest(url)
	if err != nil {
		return VulnerabilitiesResponse{}, err
	}

	resp, err := i.client.httpClient.Do(req)
	if err != nil {
		return VulnerabilitiesResponse{}, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return VulnerabilitiesResponse{}, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return VulnerabilitiesResponse{}, fmt.Errorf("unexpected response status: %s", resp.Status)
	}
	var vulnerabilitiesResponse VulnerabilitiesResponse
	err = json.NewDecoder(resp.Body).Decode(&vulnerabilitiesResponse)
	if err != nil {
		return VulnerabilitiesResponse{}, err
	}

	return vulnerabilitiesResponse, nil
}

type Registries struct {
	client *client
}

func (r *Registries) List() ([]RegistryResponse, error) {
	url := fmt.Sprintf("%s/api/v1/registries", r.client.baseURL)
	req, err := r.client.newGetRequest(url)
	if err != nil {
		return nil, err
	}

	resp, err := r.client.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response status: %s", resp.Status)
	}
	var listRegistriesResponse []RegistryResponse
	err = json.NewDecoder(resp.Body).Decode(&listRegistriesResponse)
	if err != nil {
		return nil, err
	}

	return listRegistriesResponse, nil
}

type VulnerabilitiesResponse struct {
	Count   int                             `json:"count"`
	Results []VulnerabilitiesResponseResult `json:"result"`
}

type VulnerabilitiesResponseResult struct {
	Registry            string   `json:"registry"`
	ImageRepositoryName string   `json:"image_repository_name"`
	Resource            Resource `json:"resource"`
	Name                string   `json:"name"` // e.g. CVE-2020-3910
	Description         string   `json:"description"`
	AquaSeverity        string   `json:"aqua_severity"`
	AquaVectors         string   `json:"aqua_vectors"`
	AquaScoringSystem   string   `json:"aqua_scoring_system"`
	FixVersion          string   `json:"fix_version"`
}

type Resource struct {
	Type    string `json:"type"`   // e.g. package
	Format  string `json:"format"` // e.g. deb
	Path    string `json:"path"`
	Name    string `json:"name"`    // e.g. libxml2
	Version string `json:"version"` // e.g. 2.9.4+dfsg1-7+b3
}

type RegistryResponse struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"` // e.g. HUB, API
	Description string   `json:"description"`
	URL         string   `json:"url"`
	Prefixes    []string `json:"prefixes"`
}
