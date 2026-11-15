(function () {
  const hostname = window.location.hostname;
  const isLocal = hostname === "localhost" || hostname === "127.0.0.1";
  window.SHORTIE_CONFIG = Object.freeze({
    API_BASE_URL: isLocal ? "http://127.0.0.1:8000" : "https://shortie-url.onrender.com"
  });
  window.API_URL = window.SHORTIE_CONFIG.API_BASE_URL;
})();
