use crate::credentials::Credentials;
use crate::error::Error;
use crate::result::Result;
use crate::support;

type Response = reqwest::blocking::Response;

#[derive(Debug)]
pub(super) struct Client {
    client: reqwest::blocking::Client,

    papi: String,
    sapi: String,
}

pub fn sign_header(
    digest: &mut support::hmac::HmacCtx,
    headers: &mut Vec<String>,
    header: &str,
    value: &str,
) -> Result<()> {
    let lh = header.to_lowercase();
    let m = format!("{}: {}\n", lh, value);

    digest.update(m.as_bytes())?;
    headers.push(lh);

    Ok(())
}

impl Client {
    pub fn new(c: &Credentials) -> Client {
        Client {
            papi: c.papi().clone(),
            sapi: c.sapi().clone(),

            client: reqwest::blocking::Client::new(),
        }
    }

    pub fn get(&self, url: &str) -> Result<Response> {
        match reqwest::Url::parse(url) {
            Err(e) => Err(Error::from_string(e.to_string())),
            Ok(u) => self.execute(reqwest::blocking::Request::new(
                reqwest::Method::GET,
                u,
            )),
        }
    }

    pub fn post(
        &self,
        url: &str,
        ctype: String,
        content: String,
    ) -> Result<Response> {
        self.upload(reqwest::Method::POST, url, ctype, content)
    }

    pub fn patch(
        &self,
        url: &str,
        ctype: String,
        content: String,
    ) -> Result<Response> {
        self.upload(reqwest::Method::PATCH, url, ctype, content)
    }

    fn upload(
        &self,
        method: reqwest::Method,
        url: &str,
        ctype: String,
        content: String,
    ) -> Result<Response> {
        match reqwest::Url::parse(url) {
            Err(e) => Err(Error::from_string(e.to_string())),
            Ok(u) => self.execute(
                self.client
                    .request(method, u)
                    .header("Content-Type", ctype)
                    .header("Content-Length", content.len())
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

        let mut digest = support::digest::DigestCtx::new("sha512")?;
        match req.body() {
            None => (),
            Some(body) => match body.as_bytes() {
                None => {
                    return Err(Error::from_str(
                        "streaming requests not supported",
                    ));
                }
                Some(b) => digest.update(b)?,
            },
        }
        let sum = digest.finalize()?;

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
                    format!("SHA-512={}", support::base64::encode(&sum))
                        .as_str(),
                )
                .unwrap(),
            );
        }

        let mut headers = Vec::<String>::new();
        let mut hmac =
            support::hmac::HmacCtx::new("sha512", self.sapi.as_bytes())?;
        sign_header(&mut hmac, &mut headers, "(created)", &created)?;
        sign_header(&mut hmac, &mut headers, "(request-target)", &reqtgt)?;
        for h in ["Content-Length", "Content-Type", "Date", "Digest", "Host"] {
            match req.headers().get(h) {
                None => (),
                Some(v) => {
                    sign_header(
                        &mut hmac,
                        &mut headers,
                        h,
                        v.to_str().unwrap(),
                    )?;
                }
            }
        }
        let sum = hmac.finalize()?;

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
                        support::base64::encode(&sum),
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
    use super::Response;
    use crate::credentials::Credentials;
    use crate::result::Result;

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
    fn get() -> Result<()> {
        let rsp = new_client().get(&"https://httpbin.org/get".to_string())?;
        assert!(rsp.status().is_success());
        Ok(())
    }

    fn upload(
        upload_fn: fn(&Client, &str, String, String) -> Result<Response>,
        path: &str,
    ) -> Result<()> {
        let payload = "{ \"key\": \"value\" }".to_string();

        let rsp = upload_fn(
            &new_client(),
            &format!("{}{}", "https://httpbin.org", path),
            "application/json".to_string(),
            payload.clone(),
        )?;
        assert!(rsp.status().is_success());

        let body: HttpbinResponse = rsp.json().unwrap();
        assert!(body.data == payload);

        Ok(())
    }

    #[test]
    fn post() -> Result<()> {
        upload(Client::post, &"/post")
    }

    #[test]
    fn patch() -> Result<()> {
        upload(Client::patch, &"/patch")
    }
}
