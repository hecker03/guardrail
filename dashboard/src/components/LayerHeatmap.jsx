// dashboard/src/components/LayerHeatmap.jsx

import React, { useEffect, useRef } from "react";
import * as d3 from "d3";

export default function LayerHeatmap({ data = [] }) {
  const ref = useRef();

  useEffect(() => {
    if (!data.length) return;

    const width = 640, height = 260;
    const margin = { top: 20, right: 20, bottom: 40, left: 60 };

    d3.select(ref.current).selectAll("*").remove();

    const svg = d3
      .select(ref.current)
      .attr("width", width)
      .attr("height", height);

    const layers = ["L1", "L2", "L3", "L4", "L5"];
    const labels = ["S0", "S1", "S2", "S3", "S4"];

    const x = d3.scaleBand().domain(layers).range([margin.left, width - margin.right]).padding(0.05);
    const y = d3.scaleBand().domain(labels).range([margin.top, height - margin.bottom]).padding(0.05);

    const color = d3.scaleSequential(d3.interpolateReds)
      .domain([0, d3.max(data, (d) => d.count)]);

    svg.append("g")
      .attr("transform", `translate(0,${height - margin.bottom})`)
      .call(d3.axisBottom(x));

    svg.append("g")
      .attr("transform", `translate(${margin.left},0)`)
      .call(d3.axisLeft(y));

    svg.selectAll("rect")
      .data(data)
      .join("rect")
      .attr("x", (d) => x(d.layer))
      .attr("y", (d) => y(d.label))
      .attr("width", x.bandwidth())
      .attr("height", y.bandwidth())
      .attr("fill", (d) => color(d.count))
      .append("title")
      .text((d) => `${d.layer} / ${d.label}: ${d.count}`);
  }, [data]);

  return (
    <div className="chart-card">
      <h3>Attacks by Layer × Severity</h3>
      <svg ref={ref} />
    </div>
  );
}