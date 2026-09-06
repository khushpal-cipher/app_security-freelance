// Minified-looking demo bundle with planted (fake) secrets for KeyLeak Scanner to find.
(function(){
  var config = {
    stripeKey: "sk_live_51NfakeDemoKeyDoNotUse00000000000000000000",
    openaiKey: "sk-demoFAKEkeyNotReal1234567890ABCDEF",
    awsAccessKeyId: "AKIAIOSFODNN7EXAMPLE",
    supabaseServiceRoleToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoxOTk5OTk5OTk5fQ.fakeSignatureNotValidForDemoPurposesOnly123",
    internalApiSecret: "Zx9qLpT2vR8mK5wN3jH7cF1sB6dY4eA0uV2gI9oP3rQ"
  };
  window.__DEMO_CONFIG__ = config;
  function noop(){ return 1; }
  var e = { a: 1, b: 2 };
})();
//# sourceMappingURL=app.js.map
