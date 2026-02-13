from dataclasses import dataclass, asdict


@dataclass
class PongState:
    width: int = 800
    height: int = 500
    paddle_h: int = 90
    paddle_w: int = 12
    player_y: float = 205.0
    ai_y: float = 205.0
    ball_x: float = 400.0
    ball_y: float = 250.0
    ball_vx: float = 5.0
    ball_vy: float = 3.0
    player_score: int = 0
    ai_score: int = 0


class RetroPingPongGame:
    def __init__(self):
        self.state = PongState()

    def reset(self):
        current_score_p = self.state.player_score
        current_score_ai = self.state.ai_score
        self.state = PongState(player_score=current_score_p, ai_score=current_score_ai)

    def full_reset(self):
        self.state = PongState()

    def _clamp_paddles(self):
        max_y = self.state.height - self.state.paddle_h
        self.state.player_y = max(0, min(max_y, self.state.player_y))
        self.state.ai_y = max(0, min(max_y, self.state.ai_y))

    def step(self, player_direction: int = 0):
        # player_direction: -1 (up), 0 (none), 1 (down)
        paddle_speed = 8
        self.state.player_y += player_direction * paddle_speed

        # AI follows ball
        ai_center = self.state.ai_y + self.state.paddle_h / 2
        if self.state.ball_y > ai_center + 8:
            self.state.ai_y += 5
        elif self.state.ball_y < ai_center - 8:
            self.state.ai_y -= 5

        self._clamp_paddles()

        # ball movement
        self.state.ball_x += self.state.ball_vx
        self.state.ball_y += self.state.ball_vy

        # top/bottom bounce
        if self.state.ball_y <= 0 or self.state.ball_y >= self.state.height:
            self.state.ball_vy *= -1

        # player paddle collision
        if self.state.ball_x <= 30 and self.state.player_y <= self.state.ball_y <= self.state.player_y + self.state.paddle_h:
            self.state.ball_vx = abs(self.state.ball_vx)

        # AI paddle collision
        ai_x = self.state.width - 30
        if self.state.ball_x >= ai_x and self.state.ai_y <= self.state.ball_y <= self.state.ai_y + self.state.paddle_h:
            self.state.ball_vx = -abs(self.state.ball_vx)

        # scoring
        if self.state.ball_x < 0:
            self.state.ai_score += 1
            self.reset()
        elif self.state.ball_x > self.state.width:
            self.state.player_score += 1
            self.reset()

        return asdict(self.state)

    def get_state(self):
        return asdict(self.state)
