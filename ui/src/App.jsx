import { useEffect, useState, useRef } from "react";
import axios from "axios";

function App() {
  const [articles, setArticles] = useState([]);
  const [view, setView] = useState("cti");
  const [dayOffset, setDayOffset] = useState(0);
  const [categories, setCategories] = useState([]);
  const [selectedCategories, setSelectedCategories] = useState([]);
  const [categoryCounts, setCategoryCounts] = useState({});
  const [companyInfo, setCompanyInfo] = useState({ name: "", domain: "" });
  const [companyIntel, setCompanyIntel] = useState({
    phishing: [],
    breaches: [],
    shodan: [],
    impersonation: [],
    mentions: [],
    paste_mentions: [],
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const prevArticleIds = useRef(new Set());

  // ─── Helpers ────────────────────────────────────────────────
  const formatCategory = (cat) => {
    if (!cat || typeof cat !== "string") return "uncategorized";
    return cat.replace(/_/g, " ").toLowerCase();
  };

  const formatET = (dateInput) => {
    let date;
    if (typeof dateInput === "string") {
      date = new Date(dateInput);
    } else if (dateInput instanceof Date) {
      date = dateInput;
    } else {
      date = new Date();
    }

    if (isNaN(date.getTime())) return "—";

    return new Intl.DateTimeFormat("en-US", {
      timeZone: "America/New_York",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      hour12: true,
    }).format(date);
  };

  const getCategoryBadge = (category) => {
    const cat = formatCategory(category);
    if (cat.includes("vulnerabilities") || cat.includes("exploit") || cat.includes("zero-day"))
      return "bg-red-500 text-white";
    if (cat.includes("phishing") || cat.includes("ransomware"))
      return "bg-yellow-400 text-black";
    if (cat.includes("malware") || cat.includes("threat"))
      return "bg-orange-400 text-black";
    if (cat.includes("research") || cat.includes("blog") || cat.includes("intel"))
      return "bg-blue-500 text-white";
    return "bg-gray-300 text-gray-800";
  };

  const getCvssColor = (cvssStr) => {
    if (!cvssStr) return "bg-gray-200 text-gray-800";
    
    // Extract numeric part from e.g. "7.0 (HIGH)" or "9.8"
    const match = cvssStr.match(/^(\d+\.?\d*)/);
    if (!match) return "bg-gray-200 text-gray-800";
    
    const score = parseFloat(match[1]);
    
    if (score >= 9.0) return "bg-red-600 text-white";
    if (score >= 7.0) return "bg-orange-500 text-white";
    if (score >= 4.0) return "bg-yellow-400 text-black";
    return "bg-green-500 text-white";
  };

  // FETCH GLOBAL ARTICLES (CTI view only)
  useEffect(() => {
    if (view !== "cti") return;

    setLoading(true);
    const url = `http://localhost:9000/articles?day_offset=${dayOffset}`;

    axios
      .get(url)
      .then((res) => {
        const validArticles = (res.data || []).filter(
          (a) => a && typeof a === "object" && (a.title || a.link)
        );

        const sorted = validArticles.sort(
          (a, b) => new Date(b.date) - new Date(a.date)
        );

        const newArticles = sorted.map((a) => ({
          ...a,
          isNew: !prevArticleIds.current.has(a.link || a.title || a.id || JSON.stringify(a)),
        }));

        setArticles(newArticles);
        setLoading(false);

        prevArticleIds.current = new Set(
          sorted.map((a) => a.link || a.title || a.id || JSON.stringify(a))
        );

        const counts = {};
        sorted.forEach((a) => {
          const cat = a.category || "uncategorized";
          counts[cat] = (counts[cat] || 0) + 1;
        });

        setCategories(Object.keys(counts).sort());
        setCategoryCounts(counts);
      })
      .catch((err) => {
        console.error("Failed to fetch articles:", err);
        setError("Failed to connect to CTI backend");
        setLoading(false);
      });
  }, [view, dayOffset]);

  // FETCH COMPANY BASIC INFO (once)
  useEffect(() => {
    axios
      .get("http://localhost:9000/company-info")
      .then((res) =>
        setCompanyInfo({
          name: res.data?.company_name || "Your Company",
          domain: res.data?.company_domain || "",
        })
      )
      .catch((err) => console.error("Failed to fetch company info:", err));
  }, []);

  // FETCH COMPANY-SPECIFIC INTELLIGENCE
  useEffect(() => {
    if (view !== "company") return;

    setLoading(true);

    axios
      .get("http://localhost:9000/company-intel")
      .then((res) => {
        const data = res.data || {};
        setCompanyIntel({
          phishing: Array.isArray(data.phishing) ? data.phishing : [],
          breaches: Array.isArray(data.breaches) ? data.breaches : [],
          shodan: Array.isArray(data.shodan) ? data.shodan : [],
          impersonation: Array.isArray(data.impersonation) ? data.impersonation : [],
          mentions: Array.isArray(data.mentions) ? data.mentions : [],
          paste_mentions: Array.isArray(data.paste_mentions) ? data.paste_mentions : [],
        });
        setLoading(false);
      })
      .catch((err) => {
        console.error("Company intel fetch failed:", err);
        setLoading(false);
      });
  }, [view]);

  // REMOVE "NEW" PULSE AFTER 3 SECONDS
  useEffect(() => {
    if (articles.length === 0) return;
    const timer = setTimeout(() => {
      setArticles((prev) =>
        prev.map((a) => (a.isNew ? { ...a, isNew: false } : a))
      );
    }, 3000);
    return () => clearTimeout(timer);
  }, [articles.length]);

  const toggleCategory = (cat) => {
    setSelectedCategories((prev) =>
      prev.includes(cat) ? prev.filter((c) => c !== cat) : [...prev, cat]
    );
  };

  const clearFilters = () => setSelectedCategories([]);

  const filteredArticles =
    selectedCategories.length === 0
      ? articles
      : articles.filter((a) => selectedCategories.includes(a.category || "uncategorized"));

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-xl text-blue-600 animate-pulse flex items-center gap-3">
          <span className="inline-block w-4 h-4 bg-blue-600 rounded-full animate-ping"></span>
          Loading threat intelligence...
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 text-red-600 text-xl font-medium">
        {error} — Ensure API & collector are running
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 text-gray-900">
      {/* Navigation Tabs */}
      <nav className="flex justify-center gap-6 py-6 border-b border-gray-300 bg-white shadow-sm">
        {["cti", "company"].map((tab) => {
          const isActive = view === tab;
          const label = tab === "cti" ? "Global CTI" : "Company Intelligence";
          return (
            <button
              key={tab}
              onClick={() => setView(tab)}
              className={`relative px-6 py-2 font-semibold rounded-full transition-all duration-300 focus:outline-none
                ${isActive ? "bg-red-600 text-white shadow-md scale-105" : "text-gray-800 hover:bg-blue-100 hover:text-blue-700"}`}
            >
              {label}
              {isActive && (
                <span className="absolute -bottom-1 left-1/2 transform -translate-x-1/2 w-10 h-1 bg-blue-600 rounded-full animate-slideIn" />
              )}
            </button>
          );
        })}
      </nav>

      {/* Header */}
      <header className="text-center py-8 px-4">
        {view === "cti" ? (
          <>
            <h1 className="text-5xl md:text-6xl font-bold tracking-tight">CTI Dashboard</h1>
            <p className="mt-2 text-gray-600">Real-time Cyber Threat Intelligence</p>
          </>
        ) : (
          <>
            <h1 className="text-5xl md:text-6xl font-bold leading-normal tracking-tight text-blue-700 relative z-10 pb-3">
              Company Intelligence
            </h1>
            <p className="mt-3 text-xl font-semibold text-blue-800">{companyInfo.name}</p>
            {companyInfo.domain && (
              <p className="text-gray-600 text-lg mt-1">
                <a
                  href={`https://${companyInfo.domain}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="underline hover:text-blue-700"
                >
                  {companyInfo.domain}
                </a>
              </p>
            )}
          </>
        )}
        <p className="mt-4 text-gray-600 text-lg">
          Updated: {formatET(new Date())}
        </p>
      </header>

      {/* Day selector */}
      {view === "cti" && (
        <div className="flex justify-center items-center gap-4 py-4 flex-wrap bg-white shadow-sm border-b border-gray-300">
          {["Today", "Yesterday", "2 days ago"].map((label, idx) => {
            const isActive = dayOffset === idx;
            return (
              <button
                key={idx}
                onClick={() => setDayOffset(idx)}
                className={`relative px-4 py-1 rounded-full font-medium transition-all duration-300
                  ${isActive ? "bg-blue-600 text-white shadow-md scale-105" : "text-gray-800 hover:bg-blue-100 hover:text-blue-700"}`}
              >
                {label}
                {isActive && (
                  <span className="absolute -bottom-1 left-1/2 transform -translate-x-1/2 w-8 h-1 bg-blue-600 rounded-full animate-slideIn" />
                )}
              </button>
            );
          })}
        </div>
      )}

      {/* Category filters */}
      {view === "cti" && (
        <div className="flex flex-wrap justify-center gap-2.5 py-4 px-4 bg-white shadow-sm border-b border-gray-300">
          {categories.length === 0 ? (
            <div className="text-gray-500 italic py-2">No categories detected yet</div>
          ) : (
            categories.map((cat) => {
              const isSelected = selectedCategories.includes(cat);
              const count = categoryCounts[cat] || 0;
              return (
                <button
                  key={cat}
                  onClick={() => toggleCategory(cat)}
                  className={`px-4 py-1.5 rounded-full font-medium transition-all duration-300 text-sm flex items-center gap-1.5
                    ${isSelected
                      ? "bg-blue-600 text-white shadow-md scale-105"
                      : "bg-gray-200 text-gray-800 hover:bg-blue-100 hover:text-blue-700 hover:shadow-lg hover:scale-105"}`}
                >
                  {formatCategory(cat).replace(/\b\w/g, (c) => c.toUpperCase())}
                  <span className="text-xs opacity-90 bg-white/30 px-1.5 py-0.5 rounded-full">
                    {count}
                  </span>
                </button>
              );
            })
          )}

          {selectedCategories.length > 0 && (
            <button
              onClick={clearFilters}
              className="px-4 py-1.5 rounded-full font-medium bg-red-500 text-white hover:bg-red-600 hover:shadow-lg hover:scale-105 transition-all duration-300 flex items-center gap-1.5"
            >
              Clear All
              <span className="text-xs bg-white/20 px-1.5 py-0.5 rounded-full">
                {selectedCategories.length}
              </span>
            </button>
          )}
        </div>
      )}

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pb-16 mt-8">
        {view === "cti" ? (
          <>
            {filteredArticles.length === 0 ? (
              <div className="bg-white/80 backdrop-blur-md text-center py-16 text-gray-500 rounded-xl shadow-md border border-gray-200">
                <p className="text-xl">No intelligence entries match your filters</p>
                <p className="mt-2">
                  Try removing some category filters or changing the time range.
                </p>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {filteredArticles.map((article, index) => (
                  <article
                    key={index}
                    className={`bg-white/80 backdrop-blur-md rounded-xl p-5 border border-gray-200 transition-all duration-300 hover:border-blue-600 hover:shadow-lg flex flex-col
                      ${article.isNew ? "animate-pulse border-blue-400 shadow-blue-200/50" : ""}`}
                  >
                    {/* 2×2 grid layout for metadata */}
                    <div className="grid grid-cols-2 gap-3 mb-4 items-start">
                      {/* Row 1, Col 1: Category */}
                      <span className={`px-2.5 py-1 text-xs font-semibold rounded-full ${getCategoryBadge(article.category)}`}>
                        {formatCategory(article.category).replace(/\b\w/g, (c) => c.toUpperCase())}
                      </span>

                      {/* Row 1, Col 2: Date */}
                      <div className="text-right">
                        <time className="text-xs text-gray-600 font-mono">
                          {formatET(article.date)}
                        </time>
                      </div>

                      {/* Row 2, Col 1: CVE (only if exists) */}
                      <div>
                        {article.cve_id && (
                          <span className="px-2 py-1 bg-red-50 border border-red-200 text-red-800 rounded text-xs font-medium inline-block">
                            CVE: {article.cve_id}
                          </span>
                        )}
                      </div>

                      {/* Row 2, Col 2: CVSS (only if exists) */}
                      <div className="text-right">
                        {article.cvss_score && (
                          <span
                            className={`px-2 py-1 rounded text-xs font-bold ${getCvssColor(article.cvss_score)}`}
                          >
                            CVSS {article.cvss_score}
                          </span>
                        )}
                      </div>
                    </div>

                    <h2 className="text-xl text-gray-800 font-semibold mb-3 line-clamp-2">
                      {article.title || "Untitled"}
                    </h2>

                    <p className="text-gray-700 mb-5 line-clamp-4 leading-relaxed">
                      {(article.summary || "")
                        .replace(/<[^>]*>/g, "")
                        .replace(/\s+/g, " ")
                        .trim() || "No summary available"}
                    </p>

                    <div className="flex justify-between items-center text-sm mt-auto">
                      {article.link ? (
                        <a
                          href={article.link}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1.5 text-blue-600 hover:text-blue-700 font-medium transition-colors"
                        >
                          Read full report →
                        </a>
                      ) : (
                        <span className="text-gray-500 italic">No external source</span>
                      )}

                      {article.link && (
                        <span className="text-xs text-gray-400 font-mono opacity-75">
                          {new URL(article.link).hostname.replace("www.", "")}
                        </span>
                      )}
                    </div>
                  </article>
                ))}
              </div>
            )}
          </>
        ) : (
          // Company Intelligence View (unchanged)
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {/* PHISHING */}
            <div className="bg-white rounded-xl p-5 shadow border hover:shadow-lg transition">
              <h3 className="font-semibold text-lg mb-3 text-red-600">Phishing Detection</h3>
              {companyIntel.phishing.length === 0 ? (
                <p className="text-gray-500 text-sm">No company-related phishing detected</p>
              ) : (
                companyIntel.phishing.map((item, i) => (
                  <div key={i} className="mb-4 border-b pb-3 last:border-b-0 last:mb-0">
                    <a
                      href={item[2] || "#"}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-600 hover:underline font-medium block"
                    >
                      {item[0] || "Untitled phishing alert"}
                    </a>
                    <p className="text-sm text-gray-600 mt-1 line-clamp-2">
                      {item[1] || "No description available"}
                    </p>
                  </div>
                ))
              )}
            </div>

            {/* BREACH MONITOR */}
            <div className="bg-white rounded-xl p-5 shadow border hover:shadow-lg transition">
              <h3 className="font-semibold text-lg mb-3 text-orange-600">Breach Monitoring</h3>
              {companyIntel.breaches.length === 0 ? (
                <p className="text-gray-500 text-sm">No breaches detected</p>
              ) : (
                companyIntel.breaches.map((item, i) => (
                  <div key={i} className="mb-4 border-b pb-3 last:border-b-0 last:mb-0">
                    <a
                      href={item[2] || "#"}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-600 hover:underline font-medium block"
                    >
                      {item[0] || "Untitled breach alert"}
                    </a>
                    <p className="text-sm text-gray-600 mt-1 line-clamp-2">
                      {item[1] || "No description available"}
                    </p>
                  </div>
                ))
              )}
            </div>

            {/* SHODAN */}
            <div className="bg-white rounded-xl p-5 shadow border hover:shadow-lg transition">
              <h3 className="font-semibold text-lg mb-3 text-blue-600">Shodan Exposure</h3>
              {companyIntel.shodan.length === 0 ? (
                <p className="text-gray-500 text-sm">No exposed services</p>
              ) : (
                companyIntel.shodan.map((item, i) => (
                  <div key={i} className="mb-4 border-b pb-3 last:border-b-0 last:mb-0">
                    <a
                      href={item[2] || "#"}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-600 hover:underline font-medium block"
                    >
                      {item[0] || "Untitled exposure"}
                    </a>
                    <p className="text-sm text-gray-600 mt-1 line-clamp-2">
                      {item[1] || "No description available"}
                    </p>
                  </div>
                ))
              )}
            </div>

            {/* IMPERSONATION */}
            <div className="bg-white rounded-xl p-5 shadow border hover:shadow-lg transition">
              <h3 className="font-semibold text-lg mb-3 text-purple-600">Domain Impersonation</h3>
              {companyIntel.impersonation.length === 0 ? (
                <p className="text-gray-500 text-sm">No typosquatting domains</p>
              ) : (
                companyIntel.impersonation.map((item, i) => (
                  <div key={i} className="mb-4 border-b pb-3 last:border-b-0 last:mb-0">
                    <a
                      href={item[2] || "#"}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-600 hover:underline font-medium block"
                    >
                      {item[0] || "Untitled impersonation"}
                    </a>
                    <p className="text-sm text-gray-600 mt-1 line-clamp-2">
                      {item[1] || "No description available"}
                    </p>
                  </div>
                ))
              )}
            </div>

            {/* PASTE / LEAK MENTIONS */}
            <div className="bg-white rounded-xl p-5 shadow border hover:shadow-lg transition col-span-1 md:col-span-2 lg:col-span-1">
              <h3 className="font-semibold text-lg mb-3 text-indigo-600">Paste / Leak Mentions</h3>
              {companyIntel.paste_mentions.length === 0 ? (
                <p className="text-gray-500 text-sm">No paste/leak detections found</p>
              ) : (
                companyIntel.paste_mentions.map((item, i) => (
                  <div key={i} className="mb-4 border-b pb-3 last:border-b-0 last:mb-0">
                    <a
                      href={item[2] || "#"}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-indigo-600 hover:underline font-medium block"
                    >
                      {item[0] || "Untitled paste mention"}
                    </a>
                    <p className="text-sm text-gray-600 mt-1 line-clamp-2">
                      {item[1] || "No description available"}
                    </p>
                  </div>
                ))
              )}
            </div>

            {/* BRAND MENTIONS */}
            <div className="bg-white rounded-xl p-5 shadow border hover:shadow-lg transition col-span-1 md:col-span-2 lg:col-span-1">
              <h3 className="font-semibold text-lg mb-3 text-green-600">Brand Mentions</h3>
              {companyIntel.mentions.length === 0 ? (
                <p className="text-gray-500 text-sm">No mentions detected</p>
              ) : (
                companyIntel.mentions.map((item, i) => (
                  <div key={i} className="mb-4 border-b pb-3 last:border-b-0 last:mb-0">
                    <a
                      href={item[2] || "#"}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-600 hover:underline font-medium block"
                    >
                      {item[0] || "Untitled mention"}
                    </a>
                    <p className="text-sm text-gray-600 mt-1 line-clamp-2">
                      {item[1] || "No description available"}
                    </p>
                  </div>
                ))
              )}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;