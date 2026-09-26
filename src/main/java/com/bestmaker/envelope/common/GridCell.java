package com.bestmaker.envelope.common;

/** 500m 격자 셀. 평문으로 저장되는 유일한 위치 정보다. */
public record GridCell(int row, int col) {
    public static final int SIZE_M = 500;

    public static GridCell ofMeters(double northM, double eastM) {
        return new GridCell((int) Math.floor(northM / SIZE_M), (int) Math.floor(eastM / SIZE_M));
    }

    public static GridCell parse(String id) {
        String[] p = id.split(":");
        if (p.length != 2) {
            throw new IllegalArgumentException("격자 ID 형식 오류");
        }
        return new GridCell(Integer.parseInt(p[0]), Integer.parseInt(p[1]));
    }

    public String id() {
        return row + ":" + col;
    }

    /** 체비셰프 거리(칸 수). */
    public int distance(GridCell o) {
        return Math.max(Math.abs(row - o.row), Math.abs(col - o.col));
    }

    /** 도착 전 조력자에게 보여주는 대략적 방향. 정확한 주소는 드러내지 않는다. */
    public String directionFrom(GridCell from) {
        int dr = row - from.row;
        int dc = col - from.col;
        if (dr == 0 && dc == 0) {
            return "현재 격자 안 (500m 이내)";
        }
        String ns = dr > 0 ? "북" : dr < 0 ? "남" : "";
        String ew = dc > 0 ? "동" : dc < 0 ? "서" : "";
        return ns + ew + "쪽 약 " + (distance(from) * SIZE_M) + "m";
    }
}
