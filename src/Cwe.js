import { useEffect, useState } from "react";
import cweData from "./cwe.json";

const Cwe = (props) => {
  const [cwe, setCwe] = useState([]);
  const [cweFound, setCweFound] = useState(false);

  const searchPrimary = props.rawSelectedPath[props.rawSelectedPath.length - 1];
  const searchFallback =
    props.rawSelectedPath[props.rawSelectedPath.length - 2];

  const searchpathPrimary = searchPrimary.replace(/ /g, "_").toLowerCase();
  const searchpathFallback = searchFallback
    ? searchFallback.replace(/ /g, "_").toLowerCase()
    : null;

  useEffect(() => {
    const findCweById = (data, targetId) => {
      for (let item of data) {
        if (item.id.toLowerCase() === targetId) {
          setCwe(item.cwe);
          setCweFound(true);
          return;
        }
        if (item.children) {
          findCweById(item.children, targetId);
        }
      }
    };

    setCwe([]);
    setCweFound(false);
    findCweById(cweData.content, searchpathPrimary);

    if (!cweFound && searchpathFallback) {
      findCweById(cweData.content, searchpathFallback);
    }
  }, [searchpathPrimary, searchpathFallback]);

  return (
    <div>
      {cweFound && cwe ? (
        cwe.map((code, index) => <h4 key={index}>{code}</h4>)
      ) : (
        <h3>
          No CWE found for {searchPrimary} or {searchFallback}
        </h3>
      )}
    </div>
  );
};

export default Cwe;
