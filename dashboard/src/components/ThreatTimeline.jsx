// dashboard/src/components/ThreatTimeline.jsx

import React, { useEffect, useRef } from "react";
import * as d3 from "d3";

export default function ThreatTimeline({ data = [] }) {
  const ref = useRef();

  useEffect(() => {
    if (!data.length) return;

    const width = 640, height = 260;
    const margin = { top: 20, right: 20, bottom: 30, left: 40 };

    d3.select(ref.current).selectAll("*").remove();

    const svg = d3
      .select(ref.current)
      .attr("width", width)
      .attr("height", height);

    const x = d3
      .scaleTime()
      .domain(d3.extent(data, (d) => new Date(d.timestamp)))
      .range([margin.left, width - margin.right]);

    // Stacked areas by label (S0–S4)
    const labels = ["S0", "S1", "S2", "S3", "S4"];
    const colors = d3.scaleOrdinal()
      .domain(labels)
      .range(["#10b981", "#f59e0b", "#f97316", "#ef4444", "#7f1d1d"]);

    const stack = d3.stack().keys(labels);
    const series = stack(data);

    const maxY = d3.max(series, (s) => d3.max(s, (d) => d[1])) || 10;

    const y = d3
      .scaleLinear()
      .domain([0, maxY])
      .nice()
      .range([height - margin.bottom, margin.top]);

    // X axis
    svg
      .append("g")
      .attr("transform", `translate(0,${height - margin.bottom})`)
      .call(d3.axisBottom(x).ticks(6));

    // Y axis
    svg
      .append("g")
      .attr("transform", `translate(${margin.left},0)`)
      .call(d3.axisLeft(y).ticks(5));

    const area = d3
      .area()
      .x((d) => x(new Date(d.data.timestamp)))
      .y0((d) => y(d[0]))
      .y1((d) => y(d[1]))
      .curve(d3.curveMonotoneX);

    svg
      .selectAll(".area")
      .data(series)
      .join("path")
      .attr("class", "area")
      .attr("fill", (d) => colors(d.key))
      .attr("opacity", 0.8)
      .attr("d", area);

    // Legend
    const legend = svg.append("g").attr("transform", `translate(${margin.left},10)`);
    labels.forEach((l, i) => {
      const g = legend.append("g").attr("transform", `translate(${i * 70},0)`);
      g.append("rect").attr("width", 12).attr("height", 12).attr("fill", colors(l));
      g.append("text").attr("x", 16).attr("y", 10).attr("fill", "#e5e7eb").text(l);
    });
  }, [data]);

  return (
    <div className="chart-card">
      <h3>Threat Timeline (24h)</h3>
      <svg ref={ref} />
    </div>
  );
}