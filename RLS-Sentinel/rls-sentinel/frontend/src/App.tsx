import { Route, Routes } from "react-router-dom";
import { ScanForm } from "./components/ScanForm";
import { Report } from "./pages/Report";

function Home() {
  return (
    <div className="mx-auto flex min-h-[80vh] max-w-lg flex-col justify-center px-6">
      <h1
        className="mb-2 text-center text-3xl font-bold"
        style={{ fontFamily: "Poppins, sans-serif" }}
      >
        RLS-Sentinel
      </h1>
      <p
        className="mb-8 text-center text-sm text-[#6b6a63]"
        style={{ fontFamily: "Lora, serif" }}
      >
        Find out what an unauthenticated visitor can read, write, or delete in
        your Supabase project — safely, without touching your data.
      </p>
      <ScanForm />
    </div>
  );
}

function App() {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
      <Route path="/report/:scanId" element={<Report />} />
    </Routes>
  );
}

export default App;
