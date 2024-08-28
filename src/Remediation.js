import RemediationData from "./remediation_advice.json";
import { useEffect, useState } from 'react';

const Remediation = (props) => {
  const [remediationAdvice, setRemediationAdvice] = useState([]);
  const [reference, setReference] = useState([]);
  const [remediationAdviceFound, setRemediationAdviceFound] = useState(false);

  const searchPrimary = props.rawSelectedPath[props.rawSelectedPath.length - 1];
  const searchpathPrimary = searchPrimary.replace(/ /g, "_").toLowerCase();

  useEffect(() => {
    const findRemediationAdviceById = (data, targetId) => {
      for (let item of data) {
        if (item.id.toLowerCase() === targetId) {
          setRemediationAdvice(item.remediation_advice);
          setReference(item.references);
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

  return (
    <div>
      {remediationAdviceFound ? (
        <div>
          <h2>Remediation Advice:</h2>
          <p>{remediationAdvice}</p>
          <h2>References:</h2>
          <ul>
            {reference.map((ref, index) => (
              <li key={index}><a href={ref}>{ref}</a></li>
            ))}
          </ul>
        </div>
      ) : (
        <p>No remediation advice found for the selected CWE.</p>
      )}
    </div>
  );
};

export default Remediation;
