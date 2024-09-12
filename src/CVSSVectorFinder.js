import React, { useRef, useEffect, useState } from "react";
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from "chart.js";
import { Doughnut } from "react-chartjs-2";
import Autosuggest from "react-autosuggest";
import { FaTrash, FaPlus, FaMinus, FaCopy } from "react-icons/fa";
import { toast, ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import { FaArrowRight } from "react-icons/fa";
import "./CVSSVectorFinder.css";
import Cwe from "./Cwe";
import Remediation from "./Remediation";
import cvssData from "./cvss_v3.json";
import Fuse from "fuse.js";

ChartJS.register(ArcElement, Tooltip, Legend);

const CVSS31 = {
  Weight: {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
    AC: { H: 0.44, L: 0.77 },
    PR: {
      U: { N: 0.85, L: 0.62, H: 0.27 },
      C: { N: 0.85, L: 0.68, H: 0.5 },
    },
    UI: { N: 0.85, R: 0.62 },
    S: { U: 6.42, C: 7.52 },
    CIA: { N: 0, L: 0.22, H: 0.56 },
  },
  severityRatings: [
    { name: "None", bottom: 0.0, top: 0.0 },
    { name: "Low", bottom: 0.1, top: 3.9 },
    { name: "Medium", bottom: 4.0, top: 6.9 },
    { name: "High", bottom: 7.0, top: 8.9 },
    { name: "Critical", bottom: 9.0, top: 10.0 },
  ],
};

function calculateCVSSFromVector(vector) {
  try {
    const metrics = vector.split("/");
    const metricValues = {};

    metrics.forEach((metric) => {
      const [key, value] = metric.split(":");
      metricValues[key] = value;
    });

    const AV = CVSS31.Weight.AV[metricValues["AV"]];
    const AC = CVSS31.Weight.AC[metricValues["AC"]];
    const S = metricValues["S"];
    const PR = CVSS31.Weight.PR[S][metricValues["PR"]];
    const UI = CVSS31.Weight.UI[metricValues["UI"]];
    const C = CVSS31.Weight.CIA[metricValues["C"]];
    const I = CVSS31.Weight.CIA[metricValues["I"]];
    const A = CVSS31.Weight.CIA[metricValues["A"]];

    const ImpactSubScore = 1 - (1 - C) * (1 - I) * (1 - A);
    const Impact =
      S === "C"
        ? CVSS31.Weight.S.C * ImpactSubScore
        : CVSS31.Weight.S.U * ImpactSubScore;
    const Exploitability = 8.22 * AV * AC * PR * UI;

    let BaseScore;
    if (Impact <= 0) {
      BaseScore = 0;
    } else {
      if (S === "U") {
        BaseScore = Math.min(Impact + Exploitability, 10);
      } else {
        BaseScore = Math.min(1.08 * (Impact + Exploitability), 10);
      }
    }

    return {
      success: true,
      baseMetricScore: BaseScore.toFixed(1),
      baseSeverity: determineSeverity(BaseScore),
      vectorString: vector,
      Impact: Impact.toFixed(2),
      Exploitability: Exploitability.toFixed(2),
    };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

function determineSeverity(score) {
  const ratings = CVSS31.severityRatings;
  for (let i = 0; i < ratings.length; i++) {
    if (score >= ratings[i].bottom && score <= ratings[i].top) {
      return ratings[i].name;
    }
  }
  return "Unknown";
}

const CVSSVectorFinder = () => {
  const chartRef = useRef(null);
  const [data, setData] = useState([]);
  const [suggestions, setSuggestions] = useState([]);
  const [value, setValue] = useState("");
  const [selectedVector, setSelectedVector] = useState("");
  const [calculatedScore, setCalculatedScore] = useState(null);
  const [expandedNodes, setExpandedNodes] = useState([]);
  const [selectedPath, setSelectedPath] = useState("");
  const [chartData, setChartData] = useState(null);
  const [history, setHistory] = useState([]);
  const [vulnerabilities, setVulnerabilities] = useState({});
  const [rawSelectedPath, setRawSelectedPath] = useState({});

  const handleCopy = () => {
    navigator.clipboard.writeText(calculatedScore.vectorString);
    toast.success("Copied!", {
      position: "top-right",
      autoClose: 1000,
    });
  };

  useEffect(() => {
    const vulnMap = {};
    cvssData.content.forEach((node) => buildPaths(node, vulnMap));
    setVulnerabilities(vulnMap);
    const flattenedData = flattenData(cvssData.content);
    setData(flattenedData);
  }, []);

  const buildPaths = (node, vulnMap, parentPath = "") => {
    const currentPath = parentPath
      ? `${parentPath} > ${node.id.replace(/_/g, " ")}`
      : node.id.replace(/_/g, " ");
    if (node.id) {
      vulnMap[node.id] = {
        path: currentPath,
        isHighImpact: node.cvss_v3
          ? node.cvss_v3.includes("C:H") ||
            node.cvss_v3.includes("I:H") ||
            node.cvss_v3.includes("A:H")
          : false,
      };
    }

    if (node.children) {
      node.children.forEach((child) => buildPaths(child, vulnMap, currentPath));
    }
  };

  const flattenData = (nodes, parentPath = "") => {
    return nodes.reduce((acc, node) => {
      const fullPath = parentPath ? `${parentPath}->${node.id}` : node.id;
      acc.push({
        id: node.id,
        cvss_v3: node.cvss_v3 || "",
        path: fullPath,
        children: node.children,
      });

      if (node.children) {
        acc.push(...flattenData(node.children, fullPath));
      }

      return acc;
    }, []);
  };

  const fuseOptions = {
    keys: ["id"],
    threshold: 0.4,
  };
  const getSuggestions = (value) => {
    const inputValue = value.trim().toLowerCase();
    if (inputValue.length === 0) return [];

    const fuse = new Fuse(data, fuseOptions);

    return fuse.search(inputValue).map((result) => result.item);
  };

  const getSuggestionValue = (suggestion) => suggestion.id.replace(/_/g, " ");

  const renderSuggestion = (suggestion) => {
    const isExpanded = expandedNodes.includes(suggestion.id);
    const hasChildren = suggestion.children && suggestion.children.length > 0;

    return (
      <div
        className={`suggestion ${hasChildren ? "has-children" : ""} ${
          isExpanded ? "expanded" : ""
        }`}
        onClick={(e) => {
          e.stopPropagation();
          if (hasChildren) {
            toggleNodeExpansion(suggestion.id);
          } else {
            handleSuggestionClick(suggestion);
          }
        }}
      >
        {hasChildren && (
          <span className="toggle-button">
            {isExpanded ? (
              <FaMinus className="minus-icon" />
            ) : (
              <FaPlus className="plus-icon" />
            )}
          </span>
        )}
        {suggestion.id.replace(/_/g, " ")}
        {isExpanded &&
          suggestion.children &&
          suggestion.children.map((child) => (
            <div
              key={child.id}
              className={`suggestion-child ${isExpanded ? "expanded" : ""}`}
            >
              {renderSuggestion(child)}
            </div>
          ))}
      </div>
    );
  };

  const handleSuggestionClick = (suggestion) => {
    const newFullPath =
      vulnerabilities[suggestion.id]?.path || suggestion.path || suggestion.id;
    const pathSegments = newFullPath.split(" > ");
    const displayPath = pathSegments[pathSegments.length - 1];

    if (suggestion.cvss_v3 && suggestion.cvss_v3.trim() !== "") {
      setValue(displayPath);
      setSelectedVector(suggestion.cvss_v3);

      const pathWithIcons = pathSegments.map((segment, index) => {
        let fontWeight;

        if (index === 0) {
          fontWeight = 900;
        } else if (index === 1) {
          fontWeight = 600;
        } else {
          fontWeight = 300;
        }

        return (
          <React.Fragment key={index}>
            {index > 0 && <FaArrowRight className="path-segment-icon" />}{" "}
            <span
              className="path-segment"
              style={{ fontWeight, fontSize: "1.2rem" }}
            >
              {segment}
            </span>{" "}
          </React.Fragment>
        );
      });

      setRawSelectedPath(pathSegments);
      setSelectedPath(pathWithIcons);
      calculateCVSS(suggestion.cvss_v3, newFullPath);
    } else {
      setValue(displayPath);
      setSelectedVector("");
    }

    setSuggestions([]);
  };

  const onSuggestionsFetchRequested = ({ value }) => {
    setSuggestions(getSuggestions(value));
  };

  const onSuggestionsClearRequested = () => {
    setSuggestions([]);
  };

  const onChange = (event, { newValue }) => {
    setValue(newValue);
  };

  const toggleNodeExpansion = (nodeId) => {
    setExpandedNodes((prevExpandedNodes) =>
      prevExpandedNodes.includes(nodeId)
        ? prevExpandedNodes.filter((id) => id !== nodeId)
        : [...prevExpandedNodes, nodeId]
    );
  };

  const calculateCVSS = (vector, path) => {
    const result = calculateCVSSFromVector(vector);
    if (result.success) {
      setCalculatedScore(result);

      const newHistoryEntry = {
        vector: result.vectorString,
        baseMetricScore: result.baseMetricScore,
        baseSeverity: result.baseSeverity,
        Impact: result.Impact,
        Exploitability: result.Exploitability,
        fullPath: path,
      };

      const getBackgroundColor = (severity) => {
        return severity === "Low"
          ? "rgba(255, 255, 0, 0.5)" // Yellow
          : severity === "Medium"
          ? "rgba(255, 165, 0, 0.5)" // Orange
          : severity === "High"
          ? "rgba(255, 0, 0, 0.5)" // Red
          : severity === "Critical"
          ? "rgba(139, 0, 0, 0.5)" // Dark Red
          : "rgba(52, 152, 219,0.5)"; // Default: Blue
      };
      setHistory((prevHistory) => [...prevHistory, newHistoryEntry]);
      setChartData({
        labels: ["Base Score", ""],
        datasets: [
          {
            label: "CVSS Score",
            data: [result.baseMetricScore, 10 - result.baseMetricScore],

            backgroundColor: [
              getBackgroundColor(result.baseSeverity),
              "rgba(0,0,0,0.1)",
            ],
            borderColor: [
              getBackgroundColor(result.baseSeverity),
              "rgba(0,0,0,0.1)",
            ],

            borderWidth: 1,
          },
        ],
      });
    } else {
      console.error("Error calculating CVSS:", result.error);
    }
  };

  const clear = () => {
    setValue("");
    setSelectedVector("");
    setCalculatedScore(null);
    setChartData(null);
    setSelectedPath("");
  };
  const chartCenterTextPlugin = {
    id: "centerText",
    beforeDraw: (chart) => {
      if (chart.config.options.elements.center) {
        const { ctx } = chart;
        const { width, height } = chart.chartArea;
        const centerX = width / 2 + chart.chartArea.left;
        const centerY = height / 2 + chart.chartArea.top;
        const score = chart.config.options.elements.center.text;

        ctx.save();
        ctx.font = "bold 24px Arial";
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.fillStyle = chart.config.options.elements.center.color || "#000";
        ctx.fillText(score, centerX, centerY);
      }
    },
  };
  ChartJS.register(chartCenterTextPlugin);

  const options = {
    plugins: {
      legend: {
        display: false,
        position: "bottom",
        align: "start",
        labels: {
          boxWidth: 10,
          padding: 10,
        },
      },
    },
    elements: {
      center: {
        text: calculatedScore ? `CVSS: ${calculatedScore.baseMetricScore}` : "",
        color: "#545c56",
      },
    },
    animation: {
      duration: 3500,
      easing: "easeInOutCubic",
    },
  };

  return (
    <div className="cvss-vector-finder">
      <h1>CVSS Vector & Score Finder</h1>

      <div className="autosuggest-container">
        <Autosuggest
          suggestions={suggestions}
          onSuggestionsFetchRequested={onSuggestionsFetchRequested}
          onSuggestionsClearRequested={onSuggestionsClearRequested}
          getSuggestionValue={getSuggestionValue}
          renderSuggestion={renderSuggestion}
          inputProps={{
            placeholder: "Type vulnerability here...",
            value,
            onChange,
          }}
        />
      </div>

      <div className="button-container">
        <button className="clear-button" onClick={clear}>
          <FaTrash /> Clear
        </button>
      </div>

      {value && calculatedScore && (
        <div className="horizontal-container">
          <div className="export-container" ref={chartRef}>
            {calculatedScore && (
              <div className="score-details">
                <p> {selectedPath}</p>
                <h2>
                  CVSS Score: {calculatedScore.baseMetricScore} (
                  <span
                    style={{
                      color:
                        calculatedScore.baseSeverity === "Low"
                          ? "yellow"
                          : calculatedScore.baseSeverity === "Medium"
                          ? "orange"
                          : calculatedScore.baseSeverity === "High"
                          ? "red"
                          : calculatedScore.baseSeverity === "Critical"
                          ? "darkred"
                          : "inherit",
                    }}
                  >
                    {calculatedScore.baseSeverity}
                  </span>
                  )
                </h2>

                <p>Impact Subscore: {calculatedScore.Impact}</p>
                <p>Exploitability Subscore: {calculatedScore.Exploitability}</p>

                <p>
                  <Cwe rawSelectedPath={rawSelectedPath} />
                </p>
              </div>
            )}
          </div>

          {chartData && (
            <div className="chart-container" ref={chartRef}>
              <div className="chart-wrapper">
                {chartData && <Doughnut data={chartData} options={options} />}
              </div>
              <div className="description-container">
                <p className="chart-description">
                  {calculatedScore.vectorString}
                </p>
                <FaCopy className="copy-button" onClick={handleCopy} />
                <ToastContainer />
              </div>
            </div>
          )}
        </div>
      )}

      {value && calculatedScore && (
        <Remediation rawSelectedPath={rawSelectedPath} />
      )}

      {history.length > 0 && (
        <div className="history-list">
          <div class="table-responsive">
            <h2>History</h2>
            <table>
              <thead>
                <tr>
                  <th>Vector</th>
                  <th>Base Score</th>
                  <th>Severity</th>
                  <th>Impact</th>
                  <th>Exploitability</th>
                  <th>Path</th>
                </tr>
              </thead>
              <tbody>
                {history.map((entry, index) => (
                  <tr key={index}>
                    <td>{entry.vector}</td>
                    <td>{entry.baseMetricScore}</td>
                    <td>{entry.baseSeverity}</td>
                    <td>{entry.Impact}</td>
                    <td>{entry.Exploitability}</td>
                    <td>
                      {entry.fullPath.split(" > ").map((segment, i) => (
                        <React.Fragment key={i}>
                          {i > 0 && (
                            <FaArrowRight className="history-path-segment-icon" />
                          )}
                          <span className="history-path-segment">
                            {segment}
                          </span>
                        </React.Fragment>
                      ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

export default CVSSVectorFinder;
