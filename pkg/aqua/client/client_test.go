package client_test

import (
	"net/http"

	"github.com/aquasecurity/starboard-security-operator/pkg/aqua/client"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/ghttp"
)

var _ = Describe("The Aqua API client", func() {

	var server *Server
	var aquaClient client.Clientset

	BeforeEach(func() {
		server = NewServer()
		aquaClient = client.NewClient(server.URL(), client.Authorization{
			Basic: &client.UsernameAndPassword{
				Username: "administrator",
				Password: "Password1",
			},
		})
	})

	Describe("fetching registries", func() {
		var returnedRegistries []client.RegistryResponse
		var statusCode int

		BeforeEach(func() {
			returnedRegistries = []client.RegistryResponse{
				{Name: "Docker Hub"},
				{Name: "Harbor", Prefixes: []string{"core.harbor.domain"}},
			}
			server.AppendHandlers(
				CombineHandlers(
					VerifyRequest("GET", "/api/v1/registries"),
					VerifyBasicAuth("administrator", "Password1"),
					VerifyMimeType("application/json"),
					VerifyHeader(http.Header{
						"User-Agent": []string{"StarboardSecurityOperator"},
					}),
					RespondWithJSONEncodedPtr(&statusCode, &returnedRegistries),
				),
			)
		})

		Context("when the request succeeds", func() {
			BeforeEach(func() {
				statusCode = http.StatusOK
			})

			It("should make a request to fetch registries", func() {
				registries, err := aquaClient.Registries().List()
				Expect(err).ToNot(HaveOccurred())
				Expect(registries).To(Equal(returnedRegistries))
				Expect(server.ReceivedRequests()).To(HaveLen(1))
			})
		})

		Context("when the response is unauthorized", func() {
			BeforeEach(func() {
				statusCode = http.StatusUnauthorized
			})

			It("should return error", func() {
				_, err := aquaClient.Registries().List()
				Expect(err).To(MatchError(client.ErrUnauthorized))
			})
		})
	})

	Describe("fetching vulnerabilities", func() {
		// TODO Implement test for vulnerabilities
	})

	AfterEach(func() {
		// shut down the server between tests
		server.Close()
	})

})
