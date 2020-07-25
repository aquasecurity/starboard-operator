package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

const (
	defaultTimeout = 30 * time.Second
	userAgent      = "StarboardSecurityOperator"
)

var ErrNotFound = errors.New("not found")
var ErrUnauthorized = errors.New("unauthorized")

type client struct {
	baseURL       string
	authorization Authorization
	httpClient    *http.Client
}

func (c *client) newGetRequest(url string) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json; charset=UTF-8")
	req.Header.Add("User-Agent", userAgent)
	if auth := c.authorization.Basic; auth != nil {
		req.SetBasicAuth(auth.Username, auth.Password)
	}
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

func NewClient(baseURL string, authorization Authorization) *Client {
	httpClient := &http.Client{
		Timeout: defaultTimeout,
	}
	client := &client{
		baseURL:       baseURL,
		authorization: authorization,
		httpClient:    httpClient,
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
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrUnauthorized
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
