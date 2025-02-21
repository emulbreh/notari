package notari

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type GithubKey struct {
	Id          string `json:"id"`
	Key         string `json:"key"`
	Fingerprint string `json:"fingerprint"`
}

type GithubNode struct {
	Id         string `json:"id"`
	DatabaseId int64  `json:"databaseId"`
	Name       string `json:"name"`
}

type Nodes[T any] struct {
	TotalCount uint32 `json:"totalCount"`
	Nodes      []T    `json:"nodes"`
}

type GithubTeam struct {
	GithubNode
}
type GithubOrganization struct {
	GithubNode
	//Teams Nodes[GithubTeam] `json:"teams"`
}

type GithubUserData struct {
	GithubNode
	Username      string                    `json:"login"`
	Organizations Nodes[GithubOrganization] `json:"organizations"`
	Keys          Nodes[GithubKey]          `json:"publicKeys"`
}

type GithubUserResponseData struct {
	User GithubUserData `json:"user"`
}

type GithubUserResponse struct {
	Data GithubUserResponseData `json:"data"`
}

func getClaims(user *GithubUserData) map[string]interface{} {
	claims := make(map[string]interface{})
	claims["github_name"] = user.Name
	claims["github_username"] = user.Username
	claims["github_user_id"] = user.DatabaseId
	orgs := make([]string, len(user.Organizations.Nodes))
	for i, org := range user.Organizations.Nodes {
		orgs[i] = org.Name
	}
	claims["github_organizations"] = orgs
	return claims
}

type GithubProvider struct {
	token string
}

func NewGithubProvider(token string) Provider {
	return &GithubProvider{token: token}
}

func (provider *GithubProvider) fetchUserData(username string) (*GithubUserData, error) {
	query := fmt.Sprintf(`query {
	user(login: "%[1]s") {
		login, id, name, databaseId,
		publicKeys(first: 100) {
			totalCount,
			nodes {id, fingerprint, key}
		},
		organizations(first: 100){
			nodes {
				id, name, databaseId,
				teams(first: 100, userLogins: ["%[1]s"]) {
					nodes {id, name, databaseId}
				}
			}
		}
	}
}`, username)
	body, err := json.Marshal(map[string]string{
		"query": query,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", "https://api.github.com/graphql", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v4.idl")
	req.Header.Set("Authorization", "Bearer "+provider.token)
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	userResponse := GithubUserResponse{}
	err = json.NewDecoder(response.Body).Decode(&userResponse)
	if err != nil {
		return nil, err
	}
	return &userResponse.Data.User, nil
}

func (provider *GithubProvider) GetUserInfo(username string) (*UserInfo, error) {
	userData, err := provider.fetchUserData(username)
	if err != nil {
		return nil, err
	}
	keys := make([]Key, len(userData.Keys.Nodes))
	for i, k := range userData.Keys.Nodes {
		keys[i] = Key{k.Key, k.Fingerprint}
	}
	return &UserInfo{
		Username: username,
		Keys:     keys,
		Claims:   getClaims(userData),
		Sub:      "https://github.com/" + username,
	}, nil
}
