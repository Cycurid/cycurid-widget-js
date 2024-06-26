const axiosRequest = require("./src/axiosRequest");
const checkParams = require("./src/checkParams");
const Buffer = require("buffer/").Buffer;
const fetch = require("node-fetch");
const FormData = require("form-data");

const { OAUTH_SERVER, CYCURIDWIDGET_URL } = require("./src/constants");

async function cycuridConnectInitialize(data, onSuccess, onFailure) {
  try {
    checkParams(data, onSuccess, onFailure);

    // Generate a code verifier and code challenge for PKCE
    const codeVerifier = generateRandomString(128);
    const codeChallenge = await sha256(codeVerifier);

    // Construct the scope string
    const scopeString = data.scope.join(" ");

    // Construct the widget URL
    let widgetUrl = `${CYCURIDWIDGET_URL}?client_id=${
      data.client_id
    }&origin_url=${encodeURIComponent(
      data.origin_url
    )}&scope=${encodeURIComponent(
      scopeString
    )}&redirect_uri=${encodeURIComponent(
      data.redirect_uri
    )}&code_challenge=${encodeURIComponent(
      codeChallenge
    )}&code_challenge_method=S256&action=${data.action}`;
    if (data.entity_name) {
      widgetUrl += `&entity_name=${encodeURIComponent(data.entity_name)}`;
    }

    // Open the OAuth2 consent form
    window.open(widgetUrl);

    // Listen for messages from the consent form
    window.addEventListener("message", async function listenForMessage(event) {
      if (event.origin !== new URL(CYCURIDWIDGET_URL).origin) {
        return;
      } else {
        try {
          // Exchange the authorization code for an access token
          const token = await getToken({
            code: event.data.code,
            client_id: data.client_id,
            client_secret: data.client_secret,
            redirect_uri: data.redirect_uri,
            code_verifier: codeVerifier,
          });

          if (!token) {
            onFailure(token);
          } else {
            // Retrieve user information

            const userInfo = await getUserInfo(token.token);

            onSuccess(userInfo, token.token);
          }
        } catch (error) {
          onFailure(error);
        } finally {
          window.removeEventListener("message", listenForMessage);
        }
      }
    });
  } catch (error) {
    onFailure(error);
  }
}

// Utility functions for PKCE
function generateRandomString(length) {
  const array = new Uint8Array(length);
  window.crypto.getRandomValues(array);
  return Array.from(array, (byte) => ("0" + byte.toString(16)).slice(-2)).join(
    ""
  );
}

async function sha256(plain) {
  const encoder = new TextEncoder();
  const data = encoder.encode(plain);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return base64urlEncode(hash);
}

function base64urlEncode(arrayBuffer) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(arrayBuffer)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
async function cycuridConnectLogout(token, client_id, client_secret) {
  try {
    if (typeof token !== "string" || !token) {
      throw "token is required and it must be a string";
    } else if (typeof client_id !== "string" || !client_id) {
      throw "client_id is required and it must be a string";
    } else if (typeof client_secret !== "string" || !client_secret) {
      throw "client_secret is required and it must be a string";
    } else {
      return await revokeToken({
        token,
        client_id,
        client_secret,
      });
    }
  } catch (error) {
    console.log("logout error: " + error);
  }
}

async function getCode(data, onSuccess, onFailure) {
  try {
    checkParams(data, onSuccess, onFailure);
    if (data.entity_name) {
      widget = `${CYCURIDWIDGET_URL}?client_id=${data.client_id}&origin_url=${data.origin_url}&scope=${scopeString}&entity_name=${data.entity_name}&action=${data.action}`;
    } else {
      widget = `${CYCURIDWIDGET_URL}?client_id=${data.client_id}&origin_url=${data.origin_url}&scope=${scopeString}&action=${data.action}`;
    }
    window.open(widget);
    window.addEventListener("message", async (event) => {
      if (event.origin !== CYCURIDWIDGET_URL) {
        return;
      } else {
        onSuccess(event.data);
      }
    });
  } catch (error) {
    onFailure(error);
  }
}

// need revoke token
async function revokeToken(data) {
  try {
    if (!data.client_id) {
      throw { statusText: "Missing client_id" };
    }
    if (!data.client_secret) {
      throw { statusText: "Missing client_secret" };
    }

    const info = `${data.client_id}:${data.client_secret}`;
    let buff = Buffer.from(info);
    let base64data = buff.toString("base64");

    const myHeaders = {
      Authorization: `Basic ${base64data}`,
      "Content-Type": "application/json",
      Accept: "application/json",
    };

    const requestBody = {
      token: data.token,
    };

    const requestOptions = {
      method: "POST",
      headers: myHeaders,
      body: JSON.stringify(requestBody),
    };

    const response = await fetch(
      `${OAUTH_SERVER}/v2/cycurid-connect/widget/revokeToken`,
      requestOptions
    );
    if (response.status !== 200) {
      throw response;
    }

    const result = await response.json();
    return result;
  } catch (error) {
    if (error.status) {
      return {
        status: error.status,
        statusText: error.statusText,
      };
    }
    return {
      statusText: error.statusText,
    };
  }
}

async function getUserInfo(token) {
  try {
    if (!token) {
      throw { statusText: "Token is required." };
    }

    const myHeaders = {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      Accept: "application/json",
    };

    const requestOptions = {
      method: "GET",
      headers: myHeaders,
    };

    const response = await fetch(
      `${OAUTH_SERVER}/v2/cycurid-connect/widget/getUserData`,
      requestOptions
    );
    const result = await response.json();
    return result;
  } catch (error) {
    if (error.response.status) {
      return {
        status: error.response.status,
        statusText: error.response.statusText,
        message: error.response.data.message,
      };
    }
    return {
      statusText: error.statusText,
    };
  }
}

async function getToken(data) {
  try {
    if (!data.code) {
      throw { statusText: "Missing code" };
    }
    if (!data.client_id) {
      throw { statusText: "Missing client_id" };
    }
    if (!data.client_secret) {
      throw { statusText: "Missing client_secret" };
    }
    if (!data.code_verifier) {
      throw { statusText: "Missing code_verifier" };
    }

    const info = `${data.client_id}:${data.client_secret}`;
    let buff = Buffer.from(info);
    let base64data = buff.toString("base64");

    const myHeaders = {
      Authorization: `Basic ${base64data}`,
      "Content-Type": "application/json",
      Accept: "application/json",
    };

    const requestBody = {
      grant_type: "authorization_code",
      code: data.code,
      code_verifier: data.code_verifier,
    };

    const requestOptions = {
      method: "POST",
      headers: myHeaders,
      body: JSON.stringify(requestBody),
    };

    const response = await fetch(
      `${OAUTH_SERVER}/v2/cycurid-connect/widget/token`,
      requestOptions
    );
    if (response.status !== 200) {
      throw response;
    }

    const result = await response.json();
    return result;
  } catch (error) {
    if (error.status) {
      return {
        status: error.status,
        statusText: error.statusText,
      };
    }
    return {
      statusText: error.statusText,
    };
  }
}

async function refreshToken(data) {
  try {
    if (!data.token) {
      throw { statusText: "Missing token" };
    }
    if (!data.client_id) {
      throw { statusText: "Missing client_id" };
    }
    if (!data.client_secret) {
      throw { statusText: "Missing client_secret" };
    }

    const info = `${data.client_id}:${data.client_secret}`;
    let response;

    let buff = new Buffer(info);
    let base64data = buff.toString("base64");
    var myHeaders = new fetch.Headers();
    myHeaders.append("Authorization", `Basic ${base64data}`);

    var formdata = new FormData();
    formdata.append("grant_type", "refresh_token");
    formdata.append("refresh_token", data.token);

    var requestOptions = {
      method: "POST",
      headers: myHeaders,
      body: formdata,
    };

    await fetch(`${OAUTH_SERVER}/oauth/token`, requestOptions)
      .then((response) => {
        if (response.status !== 200) {
          throw response;
        }
        return response.text();
      })
      .then((res) => {
        return JSON.parse(res);
      })
      .then((data) => {
        response = data;
      })
      .catch((error) => {
        throw error;
      });

    return response;
  } catch (error) {
    if (error.status) {
      return {
        status: error.status,
        statusText: error.statusText,
      };
    }
    return {
      statusText: error.statusText,
    };
  }
}

module.exports = {
  cycuridConnectInitialize,
  getCode,
  getUserInfo,
  getToken,
  refreshToken,
  revokeToken,
  cycuridConnectLogout,
};
