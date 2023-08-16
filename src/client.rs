use super::credentials::Credentials;
use super::error::Error;
use super::Result;

use base64::Engine;
use hmac::Mac;
use sha2::Digest;

type Response = reqwest::blocking::Response;

struct Client {
    client: reqwest::blocking::Client,

    papi: String,
    sapi: String,
}

pub fn sign_header(
    digest: &mut hmac::Hmac<sha2::Sha512>,
    headers: &mut Vec<String>,
    header: &str,
    value: &str,
) {
    let lh = header.to_lowercase();
    let m = format!("{}: {}\n", lh, value);

    digest.update(m.as_bytes());
    headers.push(lh);
}

impl Client {
    pub fn new(c: &Credentials) -> Client {
        Client {
            papi: c.papi().clone(),
            sapi: c.sapi().clone(),

            client: reqwest::blocking::Client::new(),
        }
    }

    pub fn get(&self, urls: &String) -> Result<Response> {
        match reqwest::Url::parse(urls.as_str()) {
            Err(e) => Err(Error::from_string(e.to_string())),
            Ok(u) => self.execute(reqwest::blocking::Request::new(
                reqwest::Method::GET,
                u,
            )),
        }
    }

    pub fn post(
        &self,
        urls: &String,
        ctype: String,
        content: String,
    ) -> Result<Response> {
        self.upload(reqwest::Method::POST, urls, ctype, content)
    }

    pub fn patch(
        &self,
        urls: &String,
        ctype: String,
        content: String,
    ) -> Result<Response> {
        self.upload(reqwest::Method::PATCH, urls, ctype, content)
    }

    fn upload(
        &self,
        method: reqwest::Method,
        urls: &String,
        ctype: String,
        content: String,
    ) -> Result<Response> {
        match reqwest::Url::parse(urls.as_str()) {
            Err(e) => Err(Error::from_string(e.to_string())),
            Ok(u) => self.execute(
                self.client
                    .request(method, u)
                    .header("Content-Type", ctype)
                    .body(content)
                    .build()
                    .unwrap(),
            ),
        }
    }

    fn execute(&self, mut req: reqwest::blocking::Request) -> Result<Response> {
        let now = std::time::SystemTime::now();
        let created = now
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();

        let unow: chrono::DateTime<chrono::Utc> = now.into();
        let url = req.url();
        let host =
            reqwest::header::HeaderValue::from_str(url.host_str().unwrap())
                .unwrap();

        let mut reqtgt: String;

        reqtgt = format!(
            "{} {}",
            req.method().as_str().to_string().to_lowercase(),
            url.path()
        );
        match url.query() {
            None => (),
            Some(q) => reqtgt = format!("{}?{}", reqtgt, q),
        }

        let mut dig = sha2::Sha512::new();
        match req.body() {
            None => (),
            Some(body) => match body.as_bytes() {
                None => {
                    return Err(Error::from_str(
                        "streaming requests not supported",
                    ));
                }
                Some(b) => dig.update(b),
            },
        }
        let sum = dig.finalize();

        /* scope changes to the headers */
        {
            let hdrs = req.headers_mut();

            hdrs.insert(
                "User-Agent",
                reqwest::header::HeaderValue::from_str("ubiq-rust/0.1.0")
                    .unwrap(),
            );

            hdrs.insert("Host", host);
            hdrs.insert(
                "Date",
                reqwest::header::HeaderValue::from_str(
                    unow.format("%a, %d %b %Y %H:%M:%S GMT")
                        .to_string()
                        .as_str(),
                )
                .unwrap(),
            );
            hdrs.insert(
                "Digest",
                reqwest::header::HeaderValue::from_str(
                    format!(
                        "SHA-512={}",
                        base64::engine::general_purpose::STANDARD.encode(sum)
                    )
                    .as_str(),
                )
                .unwrap(),
            );
        }

        let mut headers = Vec::<String>::new();
        let mut dig =
            hmac::Hmac::<sha2::Sha512>::new_from_slice(self.sapi.as_bytes())
                .unwrap();
        sign_header(&mut dig, &mut headers, "(request-target)", &reqtgt);
        sign_header(&mut dig, &mut headers, "(created)", &created);
        for h in ["Content-Length", "Content-Type", "Date", "Digest", "Host"] {
            match req.headers().get(h) {
                None => (),
                Some(v) => {
                    sign_header(&mut dig, &mut headers, h, v.to_str().unwrap());
                }
            }
        }
        let sum = dig.finalize();

        {
            let hdrs = req.headers_mut();

            hdrs.insert(
                "Signature",
                reqwest::header::HeaderValue::from_str(
                    format!(
                        "keyId=\"{}\"\
                             , algorithm=\"hmac-sha512\"\
                             , created={}\
                             , headers=\"{}\"\
                             , signature=\"{}\"",
                        self.papi,
                        created,
                        headers.join(" "),
                        base64::engine::general_purpose::STANDARD
                            .encode(sum.into_bytes()),
                    )
                    .as_str(),
                )
                .unwrap(),
            );
        }

        match self.client.execute(req) {
            Err(e) => Err(Error::from_string(e.to_string())),
            Ok(r) => Ok(r),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Client;
    use super::Credentials;

    #[derive(serde::Deserialize)]
    struct HttpbinResponse {
        data: String,
    }

    fn new_client() -> Client {
        Client::new(&Credentials::create(
            "abc".to_string(),
            "xyz".to_string(),
            "123".to_string(),
            None,
        ))
    }

    #[test]
    fn get() {
        let res = new_client().get(&"https://httpbin.org/get".to_string());
        assert!(res.is_ok(), "{}", res.unwrap_err().to_string());

        let rsp = res.unwrap();
        assert!(rsp.status() == reqwest::StatusCode::OK);
    }

    fn upload(
        upload_fn: fn(
            &Client,
            &String,
            String,
            String,
        ) -> super::Result<super::Response>,
        path: &str,
    ) {
        let payload = "{ \"key\": \"value\" }".to_string();

        let res = upload_fn(
            &new_client(),
            &format!("{}{}", "https://httpbin.org", path),
            "application/json".to_string(),
            payload.clone(),
        );
        assert!(res.is_ok(), "{}", res.unwrap_err().to_string());

        let rsp = res.unwrap();
        assert!(rsp.status() == reqwest::StatusCode::OK);

        let body: HttpbinResponse = rsp.json().unwrap();
        assert!(body.data == payload);
    }

    #[test]
    fn post() {
        upload(Client::post, &"/post");
    }

    #[test]
    fn patch() {
        upload(Client::patch, &"/patch");
    }
}
