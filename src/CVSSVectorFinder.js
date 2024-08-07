import React, { useState, useEffect } from 'react';
import Autosuggest from 'react-autosuggest';
import { FaPlus, FaMinus, FaTrash } from 'react-icons/fa';
import './CVSSVectorFinder.css';

const CVSS31 = {
  Weight: {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
    AC: { H: 0.44, L: 0.77 },
    PR: {
      U: { N: 0.85, L: 0.62, H: 0.27 },
      C: { N: 0.85, L: 0.68, H: 0.5 }
    },
    UI: { N: 0.85, R: 0.62 },
    S: { U: 6.42, C: 7.52 },
    CIA: { N: 0, L: 0.22, H: 0.56 }
  },
  severityRatings: [
    { name: "None", bottom: 0.0, top: 0.0 },
    { name: "Low", bottom: 0.1, top: 3.9 },
    { name: "Medium", bottom: 4.0, top: 6.9 },
    { name: "High", bottom: 7.0, top: 8.9 },
    { name: "Critical", bottom: 9.0, top: 10.0 }
  ]
};

function calculateCVSSFromVector(vector) {
  try {
    const metrics = vector.split('/');
    const metricValues = {};

    metrics.forEach(metric => {
      const [key, value] = metric.split(':');
      metricValues[key] = value;
    });

    const AV = CVSS31.Weight.AV[metricValues['AV']];
    const AC = CVSS31.Weight.AC[metricValues['AC']];
    const S = metricValues['S'];
    const PR = CVSS31.Weight.PR[S][metricValues['PR']];
    const UI = CVSS31.Weight.UI[metricValues['UI']];
    const C = CVSS31.Weight.CIA[metricValues['C']];
    const I = CVSS31.Weight.CIA[metricValues['I']];
    const A = CVSS31.Weight.CIA[metricValues['A']];

    const ImpactSubScore = 1 - ((1 - C) * (1 - I) * (1 - A));
    const Impact = S === 'C' ? CVSS31.Weight.S.C * ImpactSubScore : CVSS31.Weight.S.U * ImpactSubScore;
    const Exploitability = 8.22 * AV * AC * PR * UI;

    let BaseScore;
    if (Impact <= 0) {
      BaseScore = 0;
    } else {
      if (S === 'U') {
        BaseScore = Math.min(Impact + Exploitability, 10);
      } else {
        BaseScore = Math.min(1.08 * (Impact + Exploitability), 10);
      }
    }

    return {
      success: true,
      baseMetricScore: BaseScore.toFixed(1),
      baseSeverity: determineSeverity(BaseScore),
      vectorString: vector
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
  return 'Unknown';
}

const CVSSVectorFinder = () => {
  const [data, setData] = useState([]);
  const [suggestions, setSuggestions] = useState([]);
  const [value, setValue] = useState('');
  const [selectedVector, setSelectedVector] = useState('');
  const [calculatedScore, setCalculatedScore] = useState('');
  const [expandedNodes, setExpandedNodes] = useState([]);
  const [selectedPath, setSelectedPath] = useState('');

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await fetch(
          'https://raw.githubusercontent.com/bugcrowd/vulnerability-rating-taxonomy/master/mappings/cvss_v3/cvss_v3.json'
        );
        if (!response.ok) {
          throw new Error('Network response was not ok');
        }
        const result = await response.json();

        if (Array.isArray(result.content)) {
          const flattenedData = flattenData(result.content);
          setData(flattenedData);
          console.log('Flattened Data:', flattenedData); // Debug output
        } else {
          console.error('Unexpected data format:', result);
        }
      } catch (error) {
        console.error('Error fetching the data:', error);
      }
    };

    fetchData();
  }, []);

  const flattenData = (nodes, parentPath = '') => {
    return nodes.reduce((acc, node) => {
      const fullPath = parentPath ? `${parentPath}->${node.id}` : node.id;
      acc.push({ id: node.id, cvss_v3: node.cvss_v3 || '', path: fullPath, children: node.children });
      if (node.children) {
        acc.push(...flattenData(node.children, fullPath));
      }
      return acc;
    }, []);
  };

  const getSuggestions = (value) => {
    const inputValue = value.trim().toLowerCase();
    const inputLength = inputValue.length;

    if (inputLength === 0) return [];

    return data.filter(
      (item) => item.id.toLowerCase().slice(0, inputLength) === inputValue
    );
  };

  const getSuggestionValue = (suggestion) => suggestion.id;

  const renderSuggestion = (suggestion) => (
    <div
      className="suggestion"
      onClick={() => handleSuggestionClick(suggestion)}
    >
      {suggestion.children ? (
        <span
          className="toggle-button"
          onClick={(e) => {
            e.stopPropagation();
            toggleNodeExpansion(suggestion.id);
          }}
        >
          {expandedNodes.includes(suggestion.id) ? <FaMinus /> : <FaPlus />}
        </span>
      ) : null}
      {suggestion.id} {suggestion.cvss_v3 || ''}
      {expandedNodes.includes(suggestion.id) &&
        suggestion.children &&
        suggestion.children.map((child) => (
          <div key={child.id} className="suggestion-child">
            {renderSuggestion(child)}
          </div>
        ))}
    </div>
  );

  const handleSuggestionClick = (suggestion) => {
    if (suggestion.cvss_v3) {
      setSelectedVector(suggestion.cvss_v3);
      setSelectedPath(suggestion.path || 'N/A'); // Ensure path is set
      calculateCVSS(suggestion.cvss_v3, suggestion.path);
    } else {
      toggleNodeExpansion(suggestion.id);
    }
  };

  const toggleNodeExpansion = (id) => {
    setExpandedNodes((prevExpandedNodes) =>
      prevExpandedNodes.includes(id)
        ? prevExpandedNodes.filter((nodeId) => nodeId !== id)
        : [...prevExpandedNodes, id]
    );
  };

  const onChange = (event, { newValue }) => {
    setValue(newValue);
  };

  const onSuggestionsFetchRequested = ({ value }) => {
    setSuggestions(getSuggestions(value));
  };

  const onSuggestionsClearRequested = () => {
    setSuggestions([]);
  };

  const onSuggestionSelected = (event, { suggestion }) => {
    handleSuggestionClick(suggestion);
  };

  const inputProps = {
    placeholder: 'Enter vulnerability ID',
    value,
    onChange,
  };

  const clearInput = () => {
    setValue('');
    setSuggestions([]);
    setCalculatedScore('');
    setSelectedPath('');
  };

  const calculateCVSS = (vector, path) => {
    try {
      const output = calculateCVSSFromVector(vector);
      let result = '';
      if (output.success) {
        result = (
          `Base score: ${output.baseMetricScore}\n` +
          `Base severity: ${output.baseSeverity}\n` +
          `Vector string: ${output.vectorString}\n` 
        );
      } else {
        result = 'An error occurred in calculating the score.';
      }
      setCalculatedScore(result);
    } catch (error) {
      setCalculatedScore(`Error in calculating CVSS score: ${error.message}`);
    }
  };

  return (
    <div className="container" style={{ position: 'relative' }}>
      <h1>CVSS Vector & Score Finder</h1>
      <div className="input-container">
        <Autosuggest
          suggestions={suggestions}
          onSuggestionsFetchRequested={onSuggestionsFetchRequested}
          onSuggestionsClearRequested={onSuggestionsClearRequested}
          getSuggestionValue={getSuggestionValue}
          renderSuggestion={renderSuggestion}
          onSuggestionSelected={onSuggestionSelected}
          inputProps={inputProps}
        />
        <FaTrash className="clear-icon" onClick={clearInput} />
      </div>
      {calculatedScore && (
        <div className="calculated-score">
          <h2 style={{textAlign:'center',fontSize:'30px',color:'#04214d'}}>Calculated CVSS Score:</h2>
          <pre className='preCalc'>{calculatedScore}</pre>
        </div>
      )}
    </div>
  );
};

export default CVSSVectorFinder;
