import RemediationData from "./remediation_advice.json";
import { useEffect, useState } from "react";

const Remediation = (props) => {
  const [remediationAdvice, setRemediationAdvice] = useState("");
  const [reference, setReference] = useState([]);
  const [remediationAdviceFound, setRemediationAdviceFound] = useState(false);

  const searchPrimary = props.rawSelectedPath[props.rawSelectedPath.length - 1];
  const searchpathPrimary = searchPrimary.replace(/ /g, "_").toLowerCase();

  useEffect(() => {
    const findRemediationAdviceById = (data, targetId) => {
      for (let item of data) {
        if (item.id.toLowerCase() === targetId) {
          setRemediationAdvice(
            item.remediation_advice || "No advice available"
          );
          setReference(item.references || []);
          setRemediationAdviceFound(true);
          return;
        }

        if (item.children && item.children.length > 0) {
          findRemediationAdviceById(item.children, targetId);
        }
      }
    };

    findRemediationAdviceById(RemediationData.content, searchpathPrimary);
  }, [searchpathPrimary]);

  const formatRemediationAdvice = (advice) => {
    // Split the advice text by numbers followed by a period and a space (like "1. ", "2. ", etc.)
    const parts = advice.split(/(\d+\.\s)/).filter(Boolean);

    return parts.map((part, index) => {
      // Check if the part is a numbered line (like "1. ", "2. ", etc.)
      if (/\d+\.\s/.test(part)) {
        // Combine the number with the next content part
        const nextContent = parts[index + 1] || "";
        const combinedContent = part + nextContent;

        // Convert **...** to bold text
        const boldTextParts = combinedContent
          .split(/\*\*(.*?)\*\*/g)
          .map((chunk, i) => {
            return i % 2 === 1 ? <strong key={i}>{chunk}</strong> : chunk;
          });

        return <p key={index}>{boldTextParts}</p>;
      }
      return null; // Skip non-numbered parts
    });
  };

  return (
    <div>
      {remediationAdviceFound ? (
        <div>
          <h2>Remediation Advice:</h2>
          <div>{formatRemediationAdvice(remediationAdvice)}</div>
          <h2>References:</h2>
          <ul>
            {reference.length > 0 ? (
              reference.map((ref, index) => (
                <li key={index}>
                  <a href={ref} target="_blank" rel="noopener noreferrer">
                    {ref}
                  </a>
                </li>
              ))
            ) : (
              <li>No references available</li>
            )}
          </ul>
        </div>
      ) : (
        <p>No remediation advice found for the selected CWE.</p>
      )}
    </div>
  );
};

export default Remediation;
