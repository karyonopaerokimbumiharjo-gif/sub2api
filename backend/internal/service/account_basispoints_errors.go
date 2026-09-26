package service

import (
	"github.com/tidwall/gjson"
	"net/http"
)

const basisPointsModelPermissionCode = "basispoints_model_not_available"
const basisPointsModelPermissionMessage = "The selected account does not have Basis Points access to this model. Use an available model or an account with access to this model."

func isBasisPointsModelPermissionError(account *Account, status int, body []byte) bool {
	return account.UsesBasisPoints() && status == http.StatusForbidden &&
		gjson.GetBytes(body, "error.code").String() == basisPointsModelPermissionCode
}
