const isValidHttpUrl = require("./isValidHttpURL");

module.exports = function checkParams(data, onSuccess, onFailure) {
  try {
    if (!data.action) {
      throw { statusText: "action is required" };
    }
    if (!data.client_id) {
      throw { statusText: "client_id is required" };
    }
    if (!data.client_secret) {
      throw { statusText: "client_secret is required" };
    }
    if (!data.redirect_uri) {
      throw { statusText: "redirect_uri is required" };
    }
    if (!data.scope || !Array.isArray(data.scope) || data.scope.length === 0) {
      throw { statusText: "scope is required and must be a non-empty array" };
    }

    if (!onSuccess || typeof onSuccess !== "function") {
      throw { statusText: "onSuccess function is required" };
    }
    if (!onFailure || typeof onFailure !== "function") {
      throw { statusText: "onFailure function is required" };
    }

    // const redirectValid = isValidHttpUrl(data.redirect_uri);

    // if (!redirectValid) {
    //   throw { statusText: "Invalid redirect_uri" };
    // }

    return true;
  } catch (error) {
    throw error;
  }
};
