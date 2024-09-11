import RemediationData from "./remediation_advice.json";
import { useEffect, useState } from 'react';
import "./CVSSVectorFinder.css";

const Remediation = (props) => {
  const [remediationAdvice, setRemediationAdvice] = useState('');
  const [reference, setReference] = useState([]);
  const [remediationAdviceFound, setRemediationAdviceFound] = useState(false);

  const searchPrimary = props.rawSelectedPath[props.rawSelectedPath.length - 1];
  const searchpathPrimary = searchPrimary.replace(/ /g, "_").toLowerCase();

  useEffect(() => {
    setRemediationAdvice('');
    setReference([]);
    setRemediationAdviceFound(false);
    const findRemediationAdviceById = (data, targetId) => {
      for (let item of data) {
        if (item.id.toLowerCase() === targetId) {
          setRemediationAdvice(item.remediation_advice );
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
  
  const formatAdvice = (advice) => {
    return advice.split(/\n/).map((item, index) => {
      item = item.trim();
  
      // Replace text between ** and ` with <strong>
      const formattedItem = item
        .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>") // Existing ** to bold replacement
        .replace(/`(.*?)`/g, "<strong>$1</strong>"); // New ` to bold replacement
  
      return (
        <p key={index} dangerouslySetInnerHTML={{ __html: formattedItem }} />
      );
    });
  };

  return (
    remediationAdviceFound && (remediationAdvice || reference.length > 0) ? (
      <div className="remediation-container">
        {remediationAdvice ? (
          <div>
            <h2>Remediation Advice:</h2>
            <div>{formatAdvice(remediationAdvice)}</div>
          </div>
        ) : null}
  
        {reference.length > 0 ? (
          <div>
            <h2>References:</h2>
            <ul>
              {reference.map((ref, index) => (
                <li key={index}>
                  <a href={ref} target="_blank" rel="noopener noreferrer">
                    {ref}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </div>
    ) : null
  );}  

export default Remediation;
